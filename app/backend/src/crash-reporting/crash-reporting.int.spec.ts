import { Test, TestingModule } from '@nestjs/testing';
import { CrashReportingService } from './crash-reporting.service';
import { RedactionService } from './redaction.service';
import { CrashReportingRepository } from './crash-reporting.repository';

/**
 * Integration tests for crash reporting with real redaction
 * These tests validate the end-to-end flow including redaction
 */
describe('CrashReporting Integration', () => {
  let service: CrashReportingService;
  let repository: jest.Mocked<CrashReportingRepository>;

  beforeEach(async () => {
    const mockRepository = {
      createCrashReport: jest.fn(),
      getUserSettings: jest.fn(),
      updateUserSettings: jest.fn(),
      getCrashReportsByUser: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        CrashReportingService,
        RedactionService,
        {
          provide: CrashReportingRepository,
          useValue: mockRepository,
        },
      ],
    }).compile();

    service = module.get<CrashReportingService>(CrashReportingService);
    repository = module.get(CrashReportingRepository);
  });

  afterEach(() => {
    service.clearLogBuffer();
  });

  describe('End-to-end crash capture with redaction', () => {
    it('should never leak Stellar secret keys in any scenario', async () => {
      repository.getUserSettings.mockResolvedValue({
        userId: 'user-123',
        crashReportingEnabled: true,
        updatedAt: new Date(),
      });
      repository.createCrashReport.mockResolvedValue('report-123');

      const secretKey = 'SBZVMB74Z76QZ3ZOY3XRXEPNQN754WKRGMAG4OQIPOOB6QMHIDCNVYKY';

      // Scenario 1: Secret in error message
      service.captureLogLine('Normal log line');
      const error1 = new Error(`Failed to sign transaction with key ${secretKey}`);
      await service.captureCrash('user-123', error1);

      let capturedReport = repository.createCrashReport.mock.calls[0][0];
      expect(JSON.stringify(capturedReport)).not.toContain(secretKey);

      // Scenario 2: Secret in log lines
      service.clearLogBuffer();
      service.captureLogLine(`Using secret key: ${secretKey}`);
      const error2 = new Error('Transaction failed');
      await service.captureCrash('user-123', error2);

      capturedReport = repository.createCrashReport.mock.calls[1][0];
      expect(JSON.stringify(capturedReport)).not.toContain(secretKey);

      // Scenario 3: Secret in context
      service.clearLogBuffer();
      const error3 = new Error('Context error');
      const context = {
        stellarSecretKey: secretKey,
        config: { key: secretKey },
      };
      await service.captureCrash('user-123', error3, context);

      capturedReport = repository.createCrashReport.mock.calls[2][0];
      expect(JSON.stringify(capturedReport)).not.toContain(secretKey);
    });

    it('should never leak API keys in any scenario', async () => {
      repository.getUserSettings.mockResolvedValue({
        userId: 'user-123',
        crashReportingEnabled: true,
        updatedAt: new Date(),
      });
      repository.createCrashReport.mockResolvedValue('report-123');

      const apiKey = 'test_key_1234567890abcdefghijklmnop';

      // Scenario 1: API key in error
      const error1 = new Error(`API request failed with key ${apiKey}`);
      await service.captureCrash('user-123', error1);

      let capturedReport = repository.createCrashReport.mock.calls[0][0];
      expect(JSON.stringify(capturedReport)).not.toContain(apiKey);

      // Scenario 2: API key in logs
      service.clearLogBuffer();
      service.captureLogLine(`Authorization: Bearer ${apiKey}`);
      const error2 = new Error('Auth failed');
      await service.captureCrash('user-123', error2);

      capturedReport = repository.createCrashReport.mock.calls[1][0];
      expect(JSON.stringify(capturedReport)).not.toContain(apiKey);
    });

    it('should never leak PII (emails, IPs) in any scenario', async () => {
      repository.getUserSettings.mockResolvedValue({
        userId: 'user-123',
        crashReportingEnabled: true,
        updatedAt: new Date(),
      });
      repository.createCrashReport.mockResolvedValue('report-123');

      const email = 'sensitive@example.com';
      const ip = '203.0.113.42';

      // Scenario 1: PII in error
      const error1 = new Error(`User ${email} from ${ip} failed authentication`);
      await service.captureCrash('user-123', error1);

      let capturedReport = repository.createCrashReport.mock.calls[0][0];
      expect(JSON.stringify(capturedReport)).not.toContain(email);
      expect(JSON.stringify(capturedReport)).not.toContain(ip);

      // Scenario 2: PII in logs
      service.clearLogBuffer();
      service.captureLogLine(`Request from ${ip} for user ${email}`);
      const error2 = new Error('Request failed');
      await service.captureCrash('user-123', error2);

      capturedReport = repository.createCrashReport.mock.calls[1][0];
      expect(JSON.stringify(capturedReport)).not.toContain(email);
      expect(JSON.stringify(capturedReport)).not.toContain(ip);
    });

    it('should handle complex nested sensitive data', async () => {
      repository.getUserSettings.mockResolvedValue({
        userId: 'user-123',
        crashReportingEnabled: true,
        updatedAt: new Date(),
      });
      repository.createCrashReport.mockResolvedValue('report-123');

      const sensitiveData = {
        user: {
          email: 'user@example.com',
          profile: {
            phone: '+1-555-123-4567',
          },
        },
        auth: {
          apiKey: 'test_key_abc123',
          token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test.signature',
        },
        stellar: {
          publicKey: 'GBRPYHIL2CI3FNQ4BXLFMNDLFJUNPU2HY3ZMFSHONUCEOASW7QC7OX2H',
          secretKey: 'SBZVMB74Z76QZ3ZOY3XRXEPNQN754WKRGMAG4OQIPOOB6QMHIDCNVYKY',
        },
      };

      const error = new Error('Complex error');
      await service.captureCrash('user-123', error, sensitiveData);

      const capturedReport = repository.createCrashReport.mock.calls[0][0];
      const reportJson = JSON.stringify(capturedReport);

      // Verify no sensitive data leaked
      expect(reportJson).not.toContain('user@example.com');
      expect(reportJson).not.toContain('+1-555-123-4567');
      expect(reportJson).not.toContain('test_key_abc123');
      expect(reportJson).not.toContain('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9');
      expect(reportJson).not.toContain('GBRPYHIL2CI3FNQ4BXLFMNDLFJUNPU2HY3ZMFSHONUCEOASW7QC7OX2H');
      expect(reportJson).not.toContain('SBZVMB74Z76QZ3ZOY3XRXEPNQN754WKRGMAG4OQIPOOB6QMHIDCNVYKY');

      // Verify redaction markers are present
      expect(reportJson).toContain('[REDACTED');
    });

    it('should preserve non-sensitive data while redacting sensitive data', async () => {
      repository.getUserSettings.mockResolvedValue({
        userId: 'user-123',
        crashReportingEnabled: true,
        updatedAt: new Date(),
      });
      repository.createCrashReport.mockResolvedValue('report-123');

      const mixedData = {
        requestId: 'req-12345',
        method: 'POST',
        path: '/api/payments',
        statusCode: 500,
        apiKey: 'test_key_secret',
        userEmail: 'user@example.com',
        timestamp: '2026-05-26T10:00:00Z',
      };

      const error = new Error('Mixed data error');
      await service.captureCrash('user-123', error, mixedData);

      const capturedReport = repository.createCrashReport.mock.calls[0][0];
      const context = capturedReport.context as Record<string, unknown>;

      // Non-sensitive data should be preserved
      expect(context.requestId).toBe('req-12345');
      expect(context.method).toBe('POST');
      expect(context.path).toBe('/api/payments');
      expect(context.statusCode).toBe(500);
      expect(context.timestamp).toBe('2026-05-26T10:00:00Z');

      // Sensitive data should be redacted
      expect(context.apiKey).toBe('[REDACTED]');
      expect(context.userEmail).not.toContain('user@example.com');
    });
  });

  describe('Log export with redaction', () => {
    it('should export logs with all sensitive data redacted', async () => {
      repository.getUserSettings.mockResolvedValue({
        userId: 'user-123',
        crashReportingEnabled: true,
        updatedAt: new Date(),
      });
      repository.getCrashReportsByUser.mockResolvedValue([]);

      // Add logs with sensitive data
      service.captureLogLine('User logged in: user@example.com');
      service.captureLogLine('API key used: test_key_1234567890');
      service.captureLogLine('Stellar key: GBRPYHIL2CI3FNQ4BXLFMNDLFJUNPU2HY3ZMFSHONUCEOASW7QC7OX2H');
      service.captureLogLine('Request from IP: 192.168.1.1');
      service.captureLogLine('Normal log without sensitive data');

      const logExport = await service.exportLogs('user-123');

      expect(logExport).toBeDefined();
      const logsJson = JSON.stringify(logExport?.currentLogs);

      // Verify no sensitive data in export
      expect(logsJson).not.toContain('user@example.com');
      expect(logsJson).not.toContain('test_key_1234567890');
      expect(logsJson).not.toContain('GBRPYHIL2CI3FNQ4BXLFMNDLFJUNPU2HY3ZMFSHONUCEOASW7QC7OX2H');
      expect(logsJson).not.toContain('192.168.1.1');

      // Verify redaction markers
      expect(logsJson).toContain('[REDACTED_EMAIL]');
      expect(logsJson).toContain('[REDACTED_API_KEY]');
      expect(logsJson).toContain('[REDACTED_PUBLIC_KEY]');
      expect(logsJson).toContain('[REDACTED_IP]');

      // Verify non-sensitive data is preserved
      expect(logsJson).toContain('Normal log without sensitive data');
    });
  });

  describe('Privacy compliance', () => {
    it('should not capture any data if user has not opted in', async () => {
      repository.getUserSettings.mockResolvedValue({
        userId: 'user-123',
        crashReportingEnabled: false,
        updatedAt: new Date(),
      });

      service.captureLogLine('Sensitive log with user@example.com');
      const error = new Error('Error with test_key_1234567890');
      const context = { apiKey: 'test_key_secret' };

      const result = await service.captureCrash('user-123', error, context);

      expect(result).toBeNull();
      expect(repository.createCrashReport).not.toHaveBeenCalled();
    });

    it('should not export logs if user has not opted in', async () => {
      repository.getUserSettings.mockResolvedValue({
        userId: 'user-123',
        crashReportingEnabled: false,
        updatedAt: new Date(),
      });

      service.captureLogLine('Log line');
      const result = await service.exportLogs('user-123');

      expect(result).toBeNull();
      expect(repository.getCrashReportsByUser).not.toHaveBeenCalled();
    });
  });
});
