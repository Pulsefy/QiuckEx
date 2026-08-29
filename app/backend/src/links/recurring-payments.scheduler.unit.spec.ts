import { Test, TestingModule } from '@nestjs/testing';
import { RecurringPaymentsScheduler } from './recurring-payments.scheduler';
import { RecurringPaymentsService } from './recurring-payments.service';
import { RecurringPaymentsRepository, DbRecurringPaymentLink, DbRecurringPaymentExecution } from './recurring-payments.repository';
import { RecurringPaymentProcessor } from '../stellar/recurring-payment-processor';
import { EventEmitter2 } from '@nestjs/event-emitter';
import { JobQueueService } from '../job-queue/job-queue.service';
import { UsernamesService } from '../usernames/usernames.service';
import { SearchProfileResult } from '../supabase/supabase.service';
import { FrequencyType, RecurringStatus, ExecutionStatus } from './dto/recurring-payment.dto';

describe('RecurringPaymentsScheduler', () => {
  let scheduler: RecurringPaymentsScheduler;
  let schedulerService: jest.Mocked<RecurringPaymentsService>;
  let repository: jest.Mocked<RecurringPaymentsRepository>;
  let eventEmitter: jest.Mocked<EventEmitter2>;
  let jobQueueService: jest.Mocked<JobQueueService>;
  let usernamesService: jest.Mocked<UsernamesService>;

  const mockLink: DbRecurringPaymentLink = {
    id: 'link-1',
    username: 'testuser',
    destination: null,
    amount: 100,
    asset: 'XLM',
    asset_issuer: null,
    frequency: FrequencyType.MONTHLY,
    start_date: new Date().toISOString(),
    end_date: null,
    total_periods: 12,
    executed_count: 0,
    next_execution_date: new Date().toISOString(),
    status: RecurringStatus.ACTIVE,
    memo: null,
    memo_type: null,
    reference_id: null,
    privacy_enabled: false,
    preview_scope: null,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  };

  const mockExecution: DbRecurringPaymentExecution = {
    id: 'exec-1',
    recurring_link_id: 'link-1',
    period_number: 1,
    scheduled_at: new Date().toISOString(),
    executed_at: null,
    amount: 100,
    asset: 'XLM',
    status: ExecutionStatus.PENDING,
    transaction_hash: null,
    stellar_operation_id: null,
    failure_reason: null,
    retry_count: 0,
    last_retry_at: null,
    notification_sent: false,
    notification_sent_at: null,
    preview_scope: null,
    created_at: new Date().toISOString(),
  };

  beforeEach(async () => {
    const mockSchedulerService = {
      getLinksDueForExecution: jest.fn(),
      pauseRecurringLink: jest.fn().mockResolvedValue({}),
      markPaymentFailure: jest.fn().mockResolvedValue(undefined),
      markPaymentSuccess: jest.fn().mockResolvedValue(undefined),
    };

    const mockRepository = {
      createExecution: jest.fn().mockResolvedValue(mockExecution),
    };

    const mockPaymentProcessor = {};

    const mockEventEmitter = {
      emit: jest.fn(),
    };

    const mockJobQueueService = {
      enqueue: jest.fn().mockResolvedValue('job-1'),
    };

    const mockUsernamesService = {
      getPublicProfile: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        RecurringPaymentsScheduler,
        { provide: RecurringPaymentsService, useValue: mockSchedulerService },
        { provide: RecurringPaymentsRepository, useValue: mockRepository },
        { provide: RecurringPaymentProcessor, useValue: mockPaymentProcessor },
        { provide: EventEmitter2, useValue: mockEventEmitter },
        { provide: JobQueueService, useValue: mockJobQueueService },
        { provide: UsernamesService, useValue: mockUsernamesService },
      ],
    }).compile();

    scheduler = module.get<RecurringPaymentsScheduler>(RecurringPaymentsScheduler);
    schedulerService = module.get(RecurringPaymentsService);
    repository = module.get(RecurringPaymentsRepository);
    eventEmitter = module.get(EventEmitter2);
    jobQueueService = module.get(JobQueueService);
    usernamesService = module.get(UsernamesService);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('resolveUsernameToAddress (via executeSinglePayment)', () => {
    it('should resolve a username to a Stellar address using the usernames service', async () => {
      const mockProfile = {
        id: 'user-1',
        username: 'testuser',
        public_key: 'GABC1234567890DEF',
        created_at: new Date().toISOString(),
        last_active_at: null,
        is_public: true,
      };

      usernamesService.getPublicProfile.mockResolvedValue(mockProfile as SearchProfileResult);

      schedulerService.getLinksDueForExecution.mockResolvedValue([mockLink]);
      repository.createExecution.mockResolvedValue(mockExecution);
      jobQueueService.enqueue.mockResolvedValue('job-123');

      await scheduler.checkAndExecutePendingPayments();

      expect(usernamesService.getPublicProfile).toHaveBeenCalledWith('testuser');
      expect(jobQueueService.enqueue).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({ recipientAddress: 'GABC1234567890DEF' }),
      );
    });

    it('should pause the schedule and emit a notification for unresolvable usernames', async () => {
      usernamesService.getPublicProfile.mockResolvedValue(null);

      schedulerService.getLinksDueForExecution.mockResolvedValue([mockLink]);
      repository.createExecution.mockResolvedValue(mockExecution);

      await scheduler.checkAndExecutePendingPayments();

      expect(schedulerService.pauseRecurringLink).toHaveBeenCalledWith('link-1');
      expect(eventEmitter.emit).toHaveBeenCalledWith(
        'recurring.payment.failed',
        expect.objectContaining({
          executionId: 'exec-1',
          linkId: 'link-1',
          failureReason: expect.stringContaining('Username unresolvable or unclaimed: testuser'),
          permanent: true,
        }),
      );
      expect(jobQueueService.enqueue).not.toHaveBeenCalled();
    });

    it('should pause the schedule when username service throws an error', async () => {
      usernamesService.getPublicProfile.mockRejectedValue(new Error('Database connection failed'));

      schedulerService.getLinksDueForExecution.mockResolvedValue([mockLink]);
      repository.createExecution.mockResolvedValue(mockExecution);

      await scheduler.checkAndExecutePendingPayments();

      expect(schedulerService.pauseRecurringLink).toHaveBeenCalledWith('link-1');
      expect(eventEmitter.emit).toHaveBeenCalledWith(
        'recurring.payment.failed',
        expect.objectContaining({
          permanent: true,
        }),
      );
      expect(jobQueueService.enqueue).not.toHaveBeenCalled();
    });

    it('should use the destination address directly when set, bypassing username resolution', async () => {
      const linkWithDestination: DbRecurringPaymentLink = {
        ...mockLink,
        username: null,
        destination: 'GDEST1234567890ABC',
      };

      schedulerService.getLinksDueForExecution.mockResolvedValue([linkWithDestination]);
      repository.createExecution.mockResolvedValue(mockExecution);
      jobQueueService.enqueue.mockResolvedValue('job-456');

      await scheduler.checkAndExecutePendingPayments();

      expect(usernamesService.getPublicProfile).not.toHaveBeenCalled();
      expect(jobQueueService.enqueue).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({ recipientAddress: 'GDEST1234567890ABC' }),
      );
    });

    it('should use destination over username when both are provided', async () => {
      const linkWithBoth: DbRecurringPaymentLink = {
        ...mockLink,
        username: 'someuser',
        destination: 'GDEST9999999999XYZ',
      };

      schedulerService.getLinksDueForExecution.mockResolvedValue([linkWithBoth]);
      repository.createExecution.mockResolvedValue(mockExecution);
      jobQueueService.enqueue.mockResolvedValue('job-789');

      await scheduler.checkAndExecutePendingPayments();

      expect(usernamesService.getPublicProfile).not.toHaveBeenCalled();
      expect(jobQueueService.enqueue).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({ recipientAddress: 'GDEST9999999999XYZ' }),
      );
    });

    it('should notify the user when a username cannot be resolved', async () => {
      usernamesService.getPublicProfile.mockResolvedValue(null);

      schedulerService.getLinksDueForExecution.mockResolvedValue([mockLink]);
      repository.createExecution.mockResolvedValue(mockExecution);

      await scheduler.checkAndExecutePendingPayments();

      expect(eventEmitter.emit).toHaveBeenCalledWith(
        'recurring.payment.failed',
        expect.objectContaining({
          failureReason: expect.stringContaining('testuser'),
        }),
      );
    });
  });
});
