import { Test, TestingModule } from '@nestjs/testing';
import { RecurringPaymentsService } from './recurring-payments.service';
import { RecurringPaymentsRepository } from './recurring-payments.repository';
import { EventEmitter2 } from '@nestjs/event-emitter';
import {
  CreateRecurringPaymentLinkDto,
  FrequencyType,
  RecurringStatus,
} from './dto/recurring-payment.dto';
import { BadRequestException, NotFoundException } from '@nestjs/common';

describe('RecurringPaymentsService', () => {
  let service: RecurringPaymentsService;
  let repository: RecurringPaymentsRepository;
  let eventEmitter: EventEmitter2;

  const mockRepository = {
    createLink: jest.fn(),
    findById: jest.fn(),
    listLinks: jest.fn(),
    updateLink: jest.fn(),
    updateStatus: jest.fn(),
    deleteLink: jest.fn(),
    createExecution: jest.fn(),
    findExecutionsByLinkId: jest.fn(),
    getDueForExecution: jest.fn(),
  };

  const mockEventEmitter = {
    emit: jest.fn(),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        RecurringPaymentsService,
        {
          provide: RecurringPaymentsRepository,
          useValue: mockRepository,
        },
        {
          provide: EventEmitter2,
          useValue: mockEventEmitter,
        },
      ],
    }).compile();

    service = module.get<RecurringPaymentsService>(RecurringPaymentsService);
    repository = module.get<RecurringPaymentsRepository>(RecurringPaymentsRepository);
    eventEmitter = module.get<EventEmitter2>(EventEmitter2);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('createRecurringLink', () => {
    it('should create a recurring payment link successfully', async () => {
      const dto: CreateRecurringPaymentLinkDto = {
        amount: 100,
        asset: 'XLM',
        frequency: FrequencyType.MONTHLY,
        username: 'test_user',
        startDate: new Date(Date.now() + 60_000).toISOString(),
      };

      const mockLink = {
        id: 'test-id',
        ...dto,
        status: RecurringStatus.ACTIVE,
        executed_count: 0,
        next_execution_date: new Date(),
        created_at: new Date(),
        updated_at: new Date(),
      };

      mockRepository.createLink.mockResolvedValue(mockLink);
      mockRepository.createExecution.mockResolvedValue({ id: 'exec-id' });

      const result = await service.createRecurringLink(dto);

      expect(result).toBeDefined();
      expect(result.id).toBe('test-id');
      expect(result.status).toBe(RecurringStatus.ACTIVE);
      expect(repository.createLink).toHaveBeenCalledTimes(1);
      expect(repository.createExecution).toHaveBeenCalledTimes(1);
      expect(eventEmitter.emit).toHaveBeenCalledWith('recurring.link.created', expect.any(Object));
    });

    it('should throw error if neither username nor destination is provided', async () => {
      const dto: CreateRecurringPaymentLinkDto = {
        amount: 100,
        asset: 'XLM',
        frequency: FrequencyType.MONTHLY,
      };

      await expect(service.createRecurringLink(dto)).rejects.toThrow();
    });

    it('should throw error if amount is invalid', async () => {
      const dto: CreateRecurringPaymentLinkDto = {
        amount: -100,
        asset: 'XLM',
        frequency: FrequencyType.MONTHLY,
        username: 'test_user',
      };

      await expect(service.createRecurringLink(dto)).rejects.toThrow();
    });
  });

  describe('getRecurringLinkById', () => {
    it('should return a recurring link by ID', async () => {
      const mockLink = {
        id: 'test-id',
        username: 'test_user',
        amount: 100,
        asset: 'XLM',
        frequency: FrequencyType.MONTHLY,
        status: RecurringStatus.ACTIVE,
        executed_count: 0,
        next_execution_date: new Date(),
        created_at: new Date(),
        updated_at: new Date(),
      };

      mockRepository.findById.mockResolvedValue(mockLink);
      mockRepository.findExecutionsByLinkId.mockResolvedValue([]);

      const result = await service.getRecurringLinkById('test-id');

      expect(result).toBeDefined();
      expect(result.id).toBe('test-id');
      expect(repository.findById).toHaveBeenCalledWith('test-id');
    });

    it('should throw NotFoundException if link not found', async () => {
      mockRepository.findById.mockResolvedValue(null);

      await expect(service.getRecurringLinkById('non-existent-id')).rejects.toThrow(NotFoundException);
    });
  });

  describe('cancelRecurringLink', () => {
    it('should cancel an active recurring link', async () => {
      const mockLink = {
        id: 'test-id',
        username: 'test_user',
        status: RecurringStatus.ACTIVE,
      };

      mockRepository.findById.mockResolvedValue(mockLink);
      mockRepository.updateStatus.mockResolvedValue({ ...mockLink, status: RecurringStatus.CANCELLED });

      const result = await service.cancelRecurringLink('test-id');

      expect(result.status).toBe(RecurringStatus.CANCELLED);
      expect(repository.updateStatus).toHaveBeenCalledWith('test-id', RecurringStatus.CANCELLED);
      expect(eventEmitter.emit).toHaveBeenCalledWith('recurring.link.cancelled', expect.any(Object));
    });

    it('should throw error if link is already cancelled', async () => {
      const mockLink = {
        id: 'test-id',
        status: RecurringStatus.CANCELLED,
      };

      mockRepository.findById.mockResolvedValue(mockLink);

      await expect(service.cancelRecurringLink('test-id')).rejects.toThrow(BadRequestException);
    });
  });

  describe('pauseRecurringLink', () => {
    it('should pause an active recurring link', async () => {
      const mockLink = {
        id: 'test-id',
        status: RecurringStatus.ACTIVE,
      };

      mockRepository.findById.mockResolvedValue(mockLink);
      mockRepository.updateStatus.mockResolvedValue({ ...mockLink, status: RecurringStatus.PAUSED });

      const result = await service.pauseRecurringLink('test-id');

      expect(result.status).toBe(RecurringStatus.PAUSED);
      expect(repository.updateStatus).toHaveBeenCalledWith('test-id', RecurringStatus.PAUSED);
    });

    it('should throw error if link is not active', async () => {
      const mockLink = {
        id: 'test-id',
        status: RecurringStatus.PAUSED,
      };

      mockRepository.findById.mockResolvedValue(mockLink);

      await expect(service.pauseRecurringLink('test-id')).rejects.toThrow(BadRequestException);
    });
  });

  describe('resumeRecurringLink', () => {
    it('should resume a paused recurring link', async () => {
      const mockLink = {
        id: 'test-id',
        status: RecurringStatus.PAUSED,
      };

      mockRepository.findById.mockResolvedValue(mockLink);
      mockRepository.updateStatus.mockResolvedValue({ ...mockLink, status: RecurringStatus.ACTIVE });

      const result = await service.resumeRecurringLink('test-id');

      expect(result.status).toBe(RecurringStatus.ACTIVE);
      expect(repository.updateStatus).toHaveBeenCalledWith('test-id', RecurringStatus.ACTIVE);
    });

    it('should throw error if link is not paused', async () => {
      const mockLink = {
        id: 'test-id',
        status: RecurringStatus.ACTIVE,
      };

      mockRepository.findById.mockResolvedValue(mockLink);

      await expect(service.resumeRecurringLink('test-id')).rejects.toThrow(BadRequestException);
    });
  });

  describe('calculateNextExecutionDate', () => {
    it('should calculate next execution date for daily frequency', () => {
      const currentDate = new Date('2025-03-26');
      const nextDate = service.calculateNextExecutionDate(currentDate, FrequencyType.DAILY);
      
      expect(nextDate.getDate()).toBe(currentDate.getDate() + 1);
    });

    it('should calculate next execution date for weekly frequency', () => {
      const currentDate = new Date('2025-03-26');
      const nextDate = service.calculateNextExecutionDate(currentDate, FrequencyType.WEEKLY);
      
      expect(nextDate.getTime()).toBe(currentDate.getTime() + 7 * 24 * 60 * 60 * 1000);
    });

    it('should calculate next execution date for monthly frequency', () => {
      const currentDate = new Date('2025-03-26');
      const nextDate = service.calculateNextExecutionDate(currentDate, FrequencyType.MONTHLY);
      
      expect(nextDate.getMonth()).toBe(currentDate.getMonth() + 1);
    });

    it('should calculate next execution date for yearly frequency', () => {
      const currentDate = new Date('2025-03-26');
      const nextDate = service.calculateNextExecutionDate(currentDate, FrequencyType.YEARLY);
      
      expect(nextDate.getFullYear()).toBe(currentDate.getFullYear() + 1);
    });
  });
});
