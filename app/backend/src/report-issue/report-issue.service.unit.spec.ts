import { Test, TestingModule } from '@nestjs/testing';
import { BadRequestException } from '@nestjs/common';
import { ReportIssueService } from './report-issue.service';
import { ReportIssueRepository } from './report-issue.repository';
import { RedactionService } from '../crash-reporting/redaction.service';
import { AppConfigService } from '../config';
import { ReportIssueSubmission } from './types';

describe('ReportIssueService', () => {
  let service: ReportIssueService;
  let repository: ReportIssueRepository;
  let redactionService: RedactionService;
  let configService: AppConfigService;

  const mockReportIssueRepository = {
    createReportIssue: jest.fn(),
    getReportsByUser: jest.fn(),
    getAllReports: jest.fn(),
    getReportById: jest.fn(),
    getRecentReportCount: jest.fn(),
    deleteOldReports: jest.fn(),
  };

  const mockRedactionService = {
    redact: jest.fn(),
    redactObject: jest.fn(),
  };

  const mockConfigService = {
    reportIssueMaxPerHour: 5,
    reportIssueMaxPerDay: 20,
    reportIssueHashSalt: 'test-salt',
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        ReportIssueService,
        {
          provide: ReportIssueRepository,
          useValue: mockReportIssueRepository,
        },
        {
          provide: RedactionService,
          useValue: mockRedactionService,
        },
        {
          provide: AppConfigService,
          useValue: mockConfigService,
        },
      ],
    }).compile();

    service = module.get<ReportIssueService>(ReportIssueService);
    repository = module.get<ReportIssueRepository>(ReportIssueRepository);
    redactionService = module.get<RedactionService>(RedactionService);
    configService = module.get<AppConfigService>(AppConfigService);

    jest.clearAllMocks();
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('submitReport', () => {
    const validSubmission: ReportIssueSubmission = {
      issueType: 'bug',
      title: 'Test issue',
      description: 'Test description',
      environment: {
        platform: 'ios',
        appVersion: '1.0.0',
      },
    };

    it('should successfully submit a report', async () => {
      mockReportIssueRepository.getRecentReportCount.mockResolvedValue(0);
      mockRedactionService.redact.mockImplementation((text: string) => text);
      mockRedactionService.redactObject.mockImplementation((obj: unknown) => obj);
      mockReportIssueRepository.createReportIssue.mockResolvedValue('report_123');

      const result = await service.submitReport(validSubmission, '127.0.0.1');

      expect(result).toBe('report_123');
      expect(mockReportIssueRepository.createReportIssue).toHaveBeenCalled();
    });

    it('should redact sensitive data before submission', async () => {
      mockReportIssueRepository.getRecentReportCount.mockResolvedValue(0);
      mockRedactionService.redact.mockImplementation((text: string) => text.replace('secret', '[REDACTED]'));
      mockRedactionService.redactObject.mockImplementation((obj: unknown) => obj);
      mockReportIssueRepository.createReportIssue.mockResolvedValue('report_123');

      const submissionWithSecret: ReportIssueSubmission = {
        ...validSubmission,
        description: 'This has a secret value',
        context: { apiKey: 'secret-key' },
      };

      await service.submitReport(submissionWithSecret, '127.0.0.1');

      expect(mockRedactionService.redact).toHaveBeenCalledWith('This has a secret value');
      expect(mockRedactionService.redactObject).toHaveBeenCalledWith({ apiKey: 'secret-key' });
    });

    it('should throw BadRequestException when hourly limit is exceeded', async () => {
      mockReportIssueRepository.getRecentReportCount.mockResolvedValue(5);

      await expect(
        service.submitReport(validSubmission, '127.0.0.1'),
      ).rejects.toThrow(BadRequestException);
    });

    it('should throw BadRequestException when daily limit is exceeded', async () => {
      mockReportIssueRepository.getRecentReportCount
        .mockResolvedValueOnce(0) // hourly check passes
        .mockResolvedValueOnce(20); // daily check fails

      await expect(
        service.submitReport(validSubmission, '127.0.0.1'),
      ).rejects.toThrow(BadRequestException);
    });

    it('should persist the hashed IP address with the report', async () => {
      mockReportIssueRepository.getRecentReportCount.mockResolvedValue(0);
      mockRedactionService.redact.mockImplementation((text: string) => text);
      mockRedactionService.redactObject.mockImplementation((obj: unknown) => obj);
      mockReportIssueRepository.createReportIssue.mockResolvedValue('report_123');

      await service.submitReport(validSubmission, '127.0.0.1');

      expect(mockReportIssueRepository.createReportIssue).toHaveBeenCalledWith(
        expect.objectContaining({
          ipAddressHash: expect.any(String),
        }),
      );
    });

    it('should handle attachments in submission', async () => {
      mockReportIssueRepository.getRecentReportCount.mockResolvedValue(0);
      mockRedactionService.redact.mockImplementation((text: string) => text);
      mockRedactionService.redactObject.mockImplementation((obj: unknown) => obj);
      mockReportIssueRepository.createReportIssue.mockResolvedValue('report_123');

      const submissionWithAttachments: ReportIssueSubmission = {
        ...validSubmission,
        attachments: [
          {
            id: 'att_1',
            name: 'screenshot.png',
            type: 'image/png',
            size: 1024,
          },
        ],
      };

      await service.submitReport(submissionWithAttachments, '127.0.0.1');

      expect(mockReportIssueRepository.createReportIssue).toHaveBeenCalledWith(
        expect.objectContaining({
          attachments: submissionWithAttachments.attachments,
        }),
      );
    });
  });

  describe('getReportsByUser', () => {
    it('should return reports for a user', async () => {
      const mockReports = [
        {
          id: 'report_1',
          userId: 'user_123',
          issueType: 'bug',
          title: 'Test issue',
          description: 'Test description',
          environment: {},
          createdAt: new Date(),
        },
      ];
      mockReportIssueRepository.getReportsByUser.mockResolvedValue(mockReports);

      const result = await service.getReportsByUser('user_123');

      expect(result).toEqual(mockReports);
      expect(mockReportIssueRepository.getReportsByUser).toHaveBeenCalledWith('user_123', 10);
    });
  });

  describe('getAllReports', () => {
    it('should return all reports for admin', async () => {
      const mockReports = [
        {
          id: 'report_1',
          issueType: 'bug',
          title: 'Test issue',
          description: 'Test description',
          environment: {},
          createdAt: new Date(),
        },
      ];
      mockReportIssueRepository.getAllReports.mockResolvedValue(mockReports);

      const result = await service.getAllReports(50, 0);

      expect(result).toEqual(mockReports);
      expect(mockReportIssueRepository.getAllReports).toHaveBeenCalledWith(50, 0);
    });
  });

  describe('getReportById', () => {
    it('should return a report by ID', async () => {
      const mockReport = {
        id: 'report_1',
        issueType: 'bug',
        title: 'Test issue',
        description: 'Test description',
        environment: {},
        createdAt: new Date(),
      };
      mockReportIssueRepository.getReportById.mockResolvedValue(mockReport);

      const result = await service.getReportById('report_1');

      expect(result).toEqual(mockReport);
      expect(mockReportIssueRepository.getReportById).toHaveBeenCalledWith('report_1');
    });

    it('should return null when report not found', async () => {
      mockReportIssueRepository.getReportById.mockResolvedValue(null);

      const result = await service.getReportById('nonexistent');

      expect(result).toBeNull();
    });
  });

  describe('deleteOldReports', () => {
    it('should delete old reports', async () => {
      mockReportIssueRepository.deleteOldReports.mockResolvedValue(10);

      const result = await service.deleteOldReports(30);

      expect(result).toBe(10);
      expect(mockReportIssueRepository.deleteOldReports).toHaveBeenCalledWith(30);
    });
  });
});
