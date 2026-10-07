import {
  Controller,
  Get,
  INestApplication,
  Injectable,
  MiddlewareConsumer,
  Module,
  NestMiddleware,
  NestModule,
  Param,
} from '@nestjs/common';
import { APP_FILTER } from '@nestjs/core';
import { Test } from '@nestjs/testing';
import { NextFunction, Request, Response } from 'express';
import * as request from 'supertest';

import { SupabaseService } from '../supabase/supabase.service';
import { ApiKeysService } from '../api-keys/api-keys.service';
import { AuditService } from '../audit/audit.service';
import { ApiKeyGuard } from '../auth/guards/api-key.guard';
import { CrashCaptureFilter } from './crash-capture.filter';
import { CrashReportingModule } from './crash-reporting.module';
import { CrashReportingRepository } from './crash-reporting.repository';
import { CrashReportingService } from './crash-reporting.service';
import { runWithLogScope } from './log-capture.context';
import { RedactionService } from './redaction.service';
import { CrashReport, LogExport } from './types';

/**
 * #1063 — crash-report log capture must be scoped per request.
 *
 * Boots the real CrashReportingModule (LogCaptureMiddleware + globally
 * registered LogCaptureInterceptor) and fires concurrent requests from two
 * users whose handlers are forced to interleave, then checks that neither
 * user's crash report or log export contains the other's lines.
 */

/** Holds every caller until `parties` have arrived, forcing interleaving. */
class Barrier {
  private arrived = 0;
  private release: () => void = () => undefined;
  private readonly opened = new Promise<void>((resolve) => {
    this.release = resolve;
  });

  constructor(private readonly parties: number) {}

  arrive(): Promise<void> {
    this.arrived += 1;
    if (this.arrived >= this.parties) this.release();
    return this.opened;
  }
}

let barrier: Barrier;

@Controller('probe')
class ProbeController {
  constructor(private readonly crashReporting: CrashReportingService) {}

  @Get('crash/:user')
  async crash(@Param('user') user: string): Promise<never> {
    this.crashReporting.captureLogLine(`${user} step 1: contact ${user}@example.com`);
    await barrier.arrive(); // the other user's request logs here too
    this.crashReporting.captureLogLine(`${user} step 2`);
    throw new Error(`${user} handler failed`);
  }

  @Get('export/:user')
  async export(@Param('user') user: string): Promise<LogExport | null> {
    this.crashReporting.captureLogLine(`${user} step 1: contact ${user}@example.com`);
    await barrier.arrive();
    this.crashReporting.captureLogLine(`${user} step 2`);
    return this.crashReporting.exportLogs(user);
  }
}

/** Stand-in for auth: CrashCaptureFilter reads `request.userId`. */
@Injectable()
class TestUserMiddleware implements NestMiddleware {
  use(req: Request, _res: Response, next: NextFunction): void {
    (req as Request & { userId?: string }).userId = req.header('x-test-user');
    next();
  }
}

@Module({
  imports: [CrashReportingModule],
  controllers: [ProbeController],
  providers: [{ provide: APP_FILTER, useClass: CrashCaptureFilter }],
})
class ProbeModule implements NestModule {
  configure(consumer: MiddlewareConsumer): void {
    consumer.apply(TestUserMiddleware).forRoutes('*');
  }
}

describe('Crash reporting log capture scoping (#1063)', () => {
  let app: INestApplication;
  let service: CrashReportingService;
  let repository: {
    createCrashReport: jest.Mock;
    getUserSettings: jest.Mock;
    updateUserSettings: jest.Mock;
    getCrashReportsByUser: jest.Mock;
  };

  beforeEach(async () => {
    barrier = new Barrier(2);
    let reportCount = 0;
    repository = {
      createCrashReport: jest.fn(async () => `report-${++reportCount}`),
      getUserSettings: jest.fn(async (userId: string) => ({
        userId,
        crashReportingEnabled: true,
        updatedAt: new Date(),
      })),
      updateUserSettings: jest.fn(),
      getCrashReportsByUser: jest.fn(async () => []),
    };

    const moduleRef = await Test.createTestingModule({ imports: [ProbeModule] })
      .overrideProvider(SupabaseService)
      .useValue({})
      .overrideProvider(CrashReportingRepository)
      .useValue(repository)
      .overrideProvider(ApiKeysService)
      .useValue({
        validateApiKey: jest.fn().mockResolvedValue(true),
        validateKey: jest.fn().mockResolvedValue(true),
        verifyApiKey: jest.fn().mockResolvedValue(true),
      })
      .overrideProvider(AuditService)
      .useValue({})
      .overrideGuard(ApiKeyGuard)
      .useValue({ canActivate: () => true })
      .compile();

    app = moduleRef.createNestApplication({ logger: false });
    await app.listen(0);
    service = app.get(CrashReportingService);
  });

  afterEach(async () => {
    await app.close();
  });

  const USERS: Array<[string, string]> = [
    ['alice', 'bob'],
    ['bob', 'alice'],
  ];

  it('keeps concurrent crash reports from two users free of each other\'s log lines', async () => {
    const server = app.getHttpServer();
    const responses = await Promise.all([
      request(server).get('/probe/crash/alice').set('x-test-user', 'alice'),
      request(server).get('/probe/crash/bob').set('x-test-user', 'bob'),
    ]);
    expect(responses.map((r) => r.status)).toEqual([500, 500]);

    const reports = repository.createCrashReport.mock.calls.map(
      ([report]) => report as Omit<CrashReport, 'id' | 'createdAt'>,
    );
    expect(reports).toHaveLength(2);

    for (const [user, other] of USERS) {
      const report = reports.find((r) => r.userId === user);
      expect(report).toBeDefined();
      const lines = (report as Omit<CrashReport, 'id' | 'createdAt'>).logLines.join('\n');

      // Own lines: handler lines plus the interceptor's request/failed lines.
      expect(lines).toContain(`${user} step 1`);
      expect(lines).toContain(`${user} step 2`);
      expect(lines).toContain(`/probe/crash/${user} - Request received`);
      expect(lines).toContain(`/probe/crash/${user} - Request failed`);
      // Nothing from the other user's concurrent request.
      expect(lines).not.toContain(other);
      // Redaction still applies to the per-request buffer.
      expect(lines).not.toContain('@example.com');
      expect(lines).toContain('[REDACTED_EMAIL]');
    }
  });

  it('keeps concurrent log exports from two users free of each other\'s log lines', async () => {
    const server = app.getHttpServer();
    const [alice, bob] = await Promise.all([
      request(server).get('/probe/export/alice').set('x-test-user', 'alice'),
      request(server).get('/probe/export/bob').set('x-test-user', 'bob'),
    ]);

    for (const [user, other, response] of [
      ['alice', 'bob', alice],
      ['bob', 'alice', bob],
    ] as const) {
      expect(response.status).toBe(200);
      const body = response.body as LogExport;
      expect(body.userId).toBe(user);
      const lines = body.currentLogs.join('\n');
      expect(lines).toContain(`${user} step 1: contact [REDACTED_EMAIL]`);
      expect(lines).toContain(`${user} step 2`);
      expect(lines).not.toContain(other);
    }
  });

  it('drops lines captured outside any request scope instead of pooling them', async () => {
    service.captureLogLine('background line for someone else');
    expect(service.getLogBufferSize()).toBe(0);

    await runWithLogScope(async () => {
      await service.captureCrash('alice', new Error('boom'));
    });
    const [report] = repository.createCrashReport.mock.calls[0];
    expect(report.logLines).toEqual([]);
  });

  it('caps each scope at 100 lines independently', () => {
    runWithLogScope(() => {
      for (let i = 0; i < 150; i++) service.captureLogLine(`line ${i}`);
      expect(service.getLogBufferSize()).toBe(100);

      runWithLogScope(() => {
        expect(service.getLogBufferSize()).toBe(0);
      });
    });
  });

  it('redacts the per-request buffer exactly as RedactionService does', async () => {
    const raw = [
      'Email: user@example.com',
      'Key: GBRPYHIL2CI3FNQ4BXLFMNDLFJUNPU2HY3ZMFSHONUCEOASW7QC7OX2H',
      'Authorization: Bearer abc.def.ghi',
    ];

    await runWithLogScope(async () => {
      raw.forEach((line) => service.captureLogLine(line));
      await service.captureCrash('alice', new Error('boom'));
    });

    const [report] = repository.createCrashReport.mock.calls[0];
    expect(report.logLines).toEqual(new RedactionService().redactLogLines(raw));
  });
});
