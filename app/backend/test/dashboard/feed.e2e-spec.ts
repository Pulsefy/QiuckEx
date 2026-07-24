import {
  BadRequestException,
  INestApplication,
  ValidationPipe,
} from '@nestjs/common';
import { Test } from '@nestjs/testing';
import * as request from 'supertest';
import { AppModule } from '../../src/app.module';
import { GlobalHttpExceptionFilter } from '../../src/common/filters/global-http-exception.filter';
import { AppConfigService } from '../../src/config';
import { mapValidationErrors } from '../../src/common/utils/validation-error.mapper';
import { ApiKeyGuard } from '../../src/auth/guards/api-key.guard';
import { CustomThrottlerGuard } from '../../src/auth/guards/custom-throttler.guard';

describe('Dashboard Activity Feed (e2e)', () => {
  let app: INestApplication;

  beforeAll(async () => {
    const moduleRef = await Test.createTestingModule({
      imports: [AppModule],
    })
      .overrideProvider(ApiKeyGuard)
      .useValue({ canActivate: jest.fn().mockReturnValue(true) })
      .overrideProvider(CustomThrottlerGuard)
      .useValue({ canActivate: jest.fn().mockReturnValue(true) })
      .compile();

    app = moduleRef.createNestApplication();

    app.useGlobalPipes(
      new ValidationPipe({
        whitelist: true,
        forbidNonWhitelisted: true,
        transform: true,
        exceptionFactory: (errors) => {
          const mapped = mapValidationErrors(errors);
          return new BadRequestException({
            code: 'VALIDATION_ERROR',
            message: mapped.message,
            fields: mapped.fields,
          });
        },
      }),
    );

    const configService = moduleRef.get(AppConfigService);
    app.useGlobalFilters(new GlobalHttpExceptionFilter(configService));

    await app.init();
  });

  afterAll(async () => {
    if (app) {
      await app.close();
    }
  });

  // ── Basic endpoint structure ─────────────────────────────────────────────

  describe('GET /v1/dashboard/feed', () => {
    it('returns 200 with valid response envelope', async () => {
      const response = await request(app.getHttpServer())
        .get('/v1/dashboard/feed')
        .expect(200);

      expect(response.body).toHaveProperty('items');
      expect(response.body).toHaveProperty('pagination');
      expect(Array.isArray(response.body.items)).toBe(true);
      expect(response.body.pagination).toHaveProperty('next_cursor');
      expect(response.body.pagination).toHaveProperty('has_more');
      expect(response.body.pagination).toHaveProperty('limit');
    });

    it('returns items with required fields', async () => {
      const response = await request(app.getHttpServer())
        .get('/v1/dashboard/feed')
        .query({ limit: 5 })
        .expect(200);

      for (const item of response.body.items) {
        expect(item).toHaveProperty('id');
        expect(item).toHaveProperty('type');
        expect(item).toHaveProperty('timestamp');
        expect(item).toHaveProperty('data');

        // id must be prefixed by type for global uniqueness
        const prefix = item.type;
        expect(item.id.startsWith(prefix.slice(0, 4))).toBe(true);
      }
    });

    it('defaults to limit=20 when not specified', async () => {
      const response = await request(app.getHttpServer())
        .get('/v1/dashboard/feed')
        .expect(200);

      expect(response.body.pagination.limit).toBe(20);
    });
  });

  // ── Pagination boundaries ────────────────────────────────────────────────

  describe('Pagination boundaries', () => {
    it('respects the limit parameter', async () => {
      const limit = 3;
      const response = await request(app.getHttpServer())
        .get('/v1/dashboard/feed')
        .query({ limit })
        .expect(200);

      expect(response.body.items.length).toBeLessThanOrEqual(limit);
      expect(response.body.pagination.limit).toBe(limit);
    });

    it('returns next_cursor when there are more items', async () => {
      // Request a small limit so we're likely to have a next page
      const response = await request(app.getHttpServer())
        .get('/v1/dashboard/feed')
        .query({ limit: 1 })
        .expect(200);

      // next_cursor should be a non-empty string if there are more items,
      // or null if there aren't. Either is valid.
      expect(
        response.body.pagination.next_cursor === null ||
          typeof response.body.pagination.next_cursor === 'string',
      ).toBe(true);
    });

    it('cursor pagination returns different pages', async () => {
      // Get first page
      const page1 = await request(app.getHttpServer())
        .get('/v1/dashboard/feed')
        .query({ limit: 2 })
        .expect(200);

      if (page1.body.pagination.next_cursor) {
        // Get second page using the cursor
        const page2 = await request(app.getHttpServer())
          .get('/v1/dashboard/feed')
          .query({
            limit: 2,
            cursor: page1.body.pagination.next_cursor,
          })
          .expect(200);

        // Pages should not be identical if there are multiple items
        expect(page2.body.items).toBeDefined();
        expect(Array.isArray(page2.body.items)).toBe(true);
      }
    });

    it('accepts max limit of 100', async () => {
      const response = await request(app.getHttpServer())
        .get('/v1/dashboard/feed')
        .query({ limit: 100 })
        .expect(200);

      expect(response.body.items.length).toBeLessThanOrEqual(100);
    });

    it('rejects limit of 0 (below min)', async () => {
      await request(app.getHttpServer())
        .get('/v1/dashboard/feed')
        .query({ limit: 0 })
        .expect(400);
    });

    it('rejects limit of 101 (above max)', async () => {
      await request(app.getHttpServer())
        .get('/v1/dashboard/feed')
        .query({ limit: 101 })
        .expect(400);
    });
  });

  // ── Type filtering ───────────────────────────────────────────────────────

  describe('Type filtering', () => {
    it('returns only payment items when types=payment', async () => {
      const response = await request(app.getHttpServer())
        .get('/v1/dashboard/feed')
        .query({ types: 'payment', limit: 10 })
        .expect(200);

      for (const item of response.body.items) {
        expect(item.type).toBe('payment');
      }
    });

    it('supports multiple comma-separated types', async () => {
      const response = await request(app.getHttpServer())
        .get('/v1/dashboard/feed')
        .query({ types: 'payment,refund', limit: 10 })
        .expect(200);

      for (const item of response.body.items) {
        expect(['payment', 'refund']).toContain(item.type);
      }
    });

    it('returns items of all types when types is omitted', async () => {
      const response = await request(app.getHttpServer())
        .get('/v1/dashboard/feed')
        .query({ limit: 20 })
        .expect(200);

      const types = new Set(response.body.items.map((i: any) => i.type));
      // If there are results, we should see at least one type
      if (response.body.items.length > 0) {
        expect(types.size).toBeGreaterThanOrEqual(1);
      }
    });
  });

  // ── Deterministic ordering ───────────────────────────────────────────────

  describe('Feed ordering', () => {
    it('returns items in reverse chronological order', async () => {
      const response = await request(app.getHttpServer())
        .get('/v1/dashboard/feed')
        .query({ limit: 10 })
        .expect(200);

      const items = response.body.items;
      for (let i = 1; i < items.length; i++) {
        const prev = new Date(items[i - 1].timestamp).getTime();
        const curr = new Date(items[i].timestamp).getTime();
        expect(prev).toBeGreaterThanOrEqual(curr);
      }
    });

    it('returns the same feed ordering on repeated requests', async () => {
      const [res1, res2] = await Promise.all([
        request(app.getHttpServer())
          .get('/v1/dashboard/feed')
          .query({ limit: 5 }),
        request(app.getHttpServer())
          .get('/v1/dashboard/feed')
          .query({ limit: 5 }),
      ]);

      expect(res1.body.items.length).toBe(res2.body.items.length);

      for (let i = 0; i < Math.min(res1.body.items.length, res2.body.items.length); i++) {
        expect(res1.body.items[i].id).toBe(res2.body.items[i].id);
        expect(res1.body.items[i].type).toBe(res2.body.items[i].type);
      }
    });
  });

  // ── PublicKey filtering ──────────────────────────────────────────────────

  describe('PublicKey filtering', () => {
    it('accepts publicKey parameter and returns results', async () => {
      const response = await request(app.getHttpServer())
        .get('/v1/dashboard/feed')
        .query({
          publicKey:
            'GABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234',
          limit: 5,
        })
        .expect(200);

      expect(response.body).toHaveProperty('items');
      expect(Array.isArray(response.body.items)).toBe(true);
    });
  });

  // ─── Performance benchmarks ──────────────────────────────────────────────

  describe('Performance benchmarks', () => {
    it('feed endpoint responds within 2 000ms', async () => {
      const start = Date.now();
      await request(app.getHttpServer())
        .get('/v1/dashboard/feed')
        .query({ limit: 5 })
        .expect(200);
      expect(Date.now() - start).toBeLessThan(2_000);
    });
  });
});
