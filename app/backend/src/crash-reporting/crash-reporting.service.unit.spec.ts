import { Test, TestingModule } from '@nestjs/testing';
import { CrashReportingService } from './crash-reporting.service';
import { RedactionService } from './redaction.service';
import { CrashReportingRepository } from './crash-reporting.repository';

describe('CrashReportingService', () => {
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

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('captureLogLine', () => {
    it('should add log lines to buffer', () => {
      service.captureLogLine('Log line 1');
      service.captureLogLine('Log line 2');
      expect(service.getLogBufferSize()).toBe(2);
    });

    it('should maintain max buffer size', () => {
      // Add more than max lines
      for (let i = 0; i < 150; i++) {
        service.captureLogLine(`Log line ${i}`);
      }
      expect(service.getLogBufferSize()).toBe(100); // maxLogLines
    });
  });

  describe('captureCrash', () => {
    it('should not capture crash if user has not opted in', async () => {
      repository.getUserSettings.mockResolvedValue({
        userId: 'user-123',
        crashReportingEnabled: false,
        updatedAt: new Date(),
      });

      const error = new Error('Test error');
      const result = await service.captureCrash('user-123', error);

      expect(result).toBeNull();
      expect(repository.createCrashReport).not.toHaveBeenCalled();
    });

    it('should capture crash if user has opted in', async () => {
      repository.getUserSettings.mockResolvedValue({
        userId: 'user-123',
        crashReportingEnabled: true,
        updatedAt: new Date(),
      });
      repository.createCrashReport.mockResolvedValue('report-123');

      service.captureLogLine('Log 1');
      service.captureLogLine('Log 2');

      const error = new Error('Test error');
      const result = await service.captureCrash('user-123', error);

      expect(result).toBe('report-123');
      expect(repository.createCrashReport).toHaveBeenCalledWith(
        expect.objectContaining({
          userId: 'user-123',
          error: expect.objectContaining({
            name: 'Error',
            message: 'Test error',
          }),
          logLines: expect.arrayContaining(['Log 1', 'Log 2']),
        }),
      );
    });

    it('should redact sensitive data in error messages', async () => {
      repository.getUserSettings.mockResolvedValue({
        userId: 'user-123',
        crashReportingEnabled: true,
        updatedAt: new Date(),
      });
      repository.createCrashReport.mockResolvedValue('report-123');

      const error = new Error('Failed with key GBRPYHIL2CI3FNQ4BXLFMNDLFJUNPU2HY3ZMFSHONUCEOASW7QC7OX2H');
      await service.captureCrash('user-123', error);

      const capturedReport = repository.createCrashReport.mock.calls[0][0];
      expect(capturedReport.error.message).not.toContain('GBRPYHIL2CI3FNQ4BXLFMNDLFJUNPU2HY3ZMFSHONUCEOASW7QC7OX2H');
      expect(capturedReport.error.message).toContain('[REDACTED_PUBLIC_KEY]');
    });

    it('should redact sensitive data in log lines', async () => {
      repository.getUserSettings.mockResolvedValue({
        userId: 'user-123',
        crashReportingEnabled: true,
        updatedAt: new Date(),
      });
      repository.createCrashReport.mockResolvedValue('report-123');

      service.captureLogLine('User email: user@example.com');
      service.captureLogLine('API key: test_key_1234567890');

      const error = new Error('Test error');
      await service.captureCrash('user-123', error);

      const capturedReport = repository.createCrashReport.mock.calls[0][0];
      expect(capturedReport.logLines[0]).not.toContain('user@example.com');
      expect(capturedReport.logLines[1]).not.toContain('test_key_1234567890');
    });

    it('should redact sensitive data in context', async () => {
      repository.getUserSettings.mockResolvedValue({
        userId: 'user-123',
        crashReportingEnabled: true,
        updatedAt: new Date(),
      });
      repository.createCrashReport.mockResolvedValue('report-123');

      const error = new Error('Test error');
      const context = {
        apiKey: 'test_key_1234567890',
        userEmail: 'user@example.com',
        normalField: 'safe value',
      };

      await service.captureCrash('user-123', error, context);

      const capturedReport = repository.createCrashReport.mock.calls[0][0];
      expect(capturedReport.context).toBeDefined();
      expect((capturedReport.context as Record<string, unknown>).apiKey).toBe('[REDACTED]');
      expect((capturedReport.context as Record<string, unknown>).userEmail).not.toContain('user@example.com');
      expect((capturedReport.context as Record<string, unknown>).normalField).toBe('safe value');
    });

    it('should capture crash without userId', async () => {
      repository.createCrashReport.mockResolvedValue('report-123');

      const error = new Error('Test error');
      const result = await service.captureCrash(undefined, error);

      expect(result).toBe('report-123');
      expect(repository.getUserSettings).not.toHaveBeenCalled();
    });

    it('should handle repository errors gracefully', async () => {
      repository.getUserSettings.mockResolvedValue({
        userId: 'user-123',
        crashReportingEnabled: true,
        updatedAt: new Date(),
      });
      repository.createCrashReport.mockRejectedValue(new Error('DB error'));

      const error = new Error('Test error');
      const result = await service.captureCrash('user-123', error);

      expect(result).toBeNull();
    });
  });

  describe('getUserSettings', () => {
    it('should return user settings', async () => {
      const settings = {
        userId: 'user-123',
        crashReportingEnabled: true,
        updatedAt: new Date(),
      };
      repository.getUserSettings.mockResolvedValue(settings);

      const result = await service.getUserSettings('user-123');

      expect(result).toEqual(settings);
      expect(repository.getUserSettings).toHaveBeenCalledWith('user-123');
    });

    it('should return null if settings not found', async () => {
      repository.getUserSettings.mockResolvedValue(null);

      const result = await service.getUserSettings('user-123');

      expect(result).toBeNull();
    });
  });

  describe('updateUserSettings', () => {
    it('should update user settings', async () => {
      repository.updateUserSettings.mockResolvedValue();

      await service.updateUserSettings('user-123', true);

      expect(repository.updateUserSettings).toHaveBeenCalledWith('user-123', true);
    });
  });

  describe('exportLogs', () => {
    it('should export logs if user has opted in', async () => {
      repository.getUserSettings.mockResolvedValue({
        userId: 'user-123',
        crashReportingEnabled: true,
        updatedAt: new Date(),
      });
      repository.getCrashReportsByUser.mockResolvedValue([
        {
          id: 'report-1',
          userId: 'user-123',
          error: { name: 'Error', message: 'Test error' },
          logLines: ['Log 1'],
          timestamp: new Date(),
          createdAt: new Date(),
        },
      ]);

      service.captureLogLine('Current log 1');
      service.captureLogLine('Current log 2');

      const result = await service.exportLogs('user-123');

      expect(result).toBeDefined();
      expect(result?.userId).toBe('user-123');
      expect(result?.currentLogs).toHaveLength(2);
      expect(result?.crashReports).toHaveLength(1);
    });

    it('should not export logs if user has not opted in', async () => {
      repository.getUserSettings.mockResolvedValue({
        userId: 'user-123',
        crashReportingEnabled: false,
        updatedAt: new Date(),
      });

      const result = await service.exportLogs('user-123');

      expect(result).toBeNull();
      expect(repository.getCrashReportsByUser).not.toHaveBeenCalled();
    });

    it('should redact current logs in export', async () => {
      repository.getUserSettings.mockResolvedValue({
        userId: 'user-123',
        crashReportingEnabled: true,
        updatedAt: new Date(),
      });
      repository.getCrashReportsByUser.mockResolvedValue([]);

      service.captureLogLine('Email: user@example.com');
      service.captureLogLine('Key: GBRPYHIL2CI3FNQ4BXLFMNDLFJUNPU2HY3ZMFSHONUCEOASW7QC7OX2H');

      const result = await service.exportLogs('user-123');

      expect(result?.currentLogs[0]).not.toContain('user@example.com');
      expect(result?.currentLogs[1]).not.toContain('GBRPYHIL2CI3FNQ4BXLFMNDLFJUNPU2HY3ZMFSHONUCEOASW7QC7OX2H');
    });

    it('should handle export errors gracefully', async () => {
      repository.getUserSettings.mockRejectedValue(new Error('DB error'));

      const result = await service.exportLogs('user-123');

      expect(result).toBeNull();
    });
  });

  describe('getCrashReports', () => {
    it('should return crash reports if user has opted in', async () => {
      repository.getUserSettings.mockResolvedValue({
        userId: 'user-123',
        crashReportingEnabled: true,
        updatedAt: new Date(),
      });
      const reports = [
        {
          id: 'report-1',
          userId: 'user-123',
          error: { name: 'Error', message: 'Test error' },
          logLines: ['Log 1'],
          timestamp: new Date(),
          createdAt: new Date(),
        },
      ];
      repository.getCrashReportsByUser.mockResolvedValue(reports);

      const result = await service.getCrashReports('user-123');

      expect(result).toEqual(reports);
    });

    it('should return empty array if user has not opted in', async () => {
      repository.getUserSettings.mockResolvedValue({
        userId: 'user-123',
        crashReportingEnabled: false,
        updatedAt: new Date(),
      });

      const result = await service.getCrashReports('user-123');

      expect(result).toEqual([]);
      expect(repository.getCrashReportsByUser).not.toHaveBeenCalled();
    });
  });
});
