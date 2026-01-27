import { Test, TestingModule } from '@nestjs/testing';
import { EventEmitterModule, EventEmitter2 } from '@nestjs/event-emitter';
import { NotificationService } from './notification.service';

// Helper to wait for async events
const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

describe('NotificationService (Event Hook Verification)', () => {
  let service: NotificationService;
  let eventEmitter: EventEmitter2;
  let module: TestingModule;

  const mockLogger = {
    log: jest.fn(),
    debug: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
  };

  beforeEach(async () => {
    module = await Test.createTestingModule({
      imports: [EventEmitterModule.forRoot({
        wildcard: true,
        delimiter: '.',
      })],
      providers: [NotificationService],
    }).compile();

    await module.init();

    service = module.get<NotificationService>(NotificationService);
    eventEmitter = module.get<EventEmitter2>(EventEmitter2);


    Object.defineProperty(service, 'logger', {
      value: mockLogger,
      writable: true,
    });
  });

  afterEach(async () => {
    jest.clearAllMocks();
    await module.close();
  });

  it('should react to "username.claimed" event and log intent', async () => {
    const payload = {
      username: 'test_user',
      publicKey: 'G...123',
      timestamp: new Date().toISOString(),
    };

    await eventEmitter.emitAsync('username.claimed', payload);
    
    await sleep(200);

    expect(mockLogger.log).toHaveBeenCalledWith(
      expect.stringContaining('Intent')
    );
  });

  it('should react to "payment.received" event and log intent', async () => {
    const payload = {
      txHash: '0xabc123',
      amount: '100',
      sender: 'G...sender',
    };

    await eventEmitter.emitAsync('payment.received', payload);
    
    await sleep(200);

    expect(mockLogger.log).toHaveBeenCalledWith(
      expect.stringContaining('Intent')
    );
  });
});