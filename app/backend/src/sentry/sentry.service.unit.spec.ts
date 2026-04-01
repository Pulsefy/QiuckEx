
/* eslint-disable @typescript-eslint/no-explicit-any */
import { Test, TestingModule } from '@nestjs/testing';
import { SentryService } from './sentry.service';

// ✅ Centralized mocks
const mockGetClient = jest.fn();
const mockCaptureException = jest.fn();
const mockCaptureMessage = jest.fn();
const mockSetUser = jest.fn();
const mockAddBreadcrumb = jest.fn();
const mockSetTag = jest.fn();
const mockSetExtra = jest.fn();

// ✅ Mock @sentry/nestjs
jest.mock('@sentry/nestjs', () => ({
  getClient: mockGetClient,
  captureException: (...args: any[]) => {
    mockCaptureException(...args);
    return 'mock-event-id';
  },
  captureMessage: (...args: any[]) => {
    mockCaptureMessage(...args);
    return 'mock-event-id';
  },
  setUser: mockSetUser,
  addBreadcrumb: mockAddBreadcrumb,
  setTag: mockSetTag,
  setExtra: mockSetExtra,
}));

describe('SentryService', () => {
  let service: SentryService;

  beforeEach(async () => {
    jest.clearAllMocks(); // ✅ reset BEFORE module creation

    const module: TestingModule = await Test.createTestingModule({
      providers: [SentryService],
    }).compile();

    service = module.get<SentryService>(SentryService);
  });

  describe('isEnabled', () => {
    it('should return true when Sentry client exists', () => {
      mockGetClient.mockReturnValue({});
      expect(service.isEnabled).toBe(true);
    });

    it('should return false when Sentry client is undefined', () => {
      mockGetClient.mockReturnValue(undefined);
      expect(service.isEnabled).toBe(false);
    });
  });

  describe('captureException', () => {
    it('should capture exception when enabled', () => {
      mockGetClient.mockReturnValue({});

      const error = new Error('Test error');
      const result = service.captureException(error, { orderId: '123' });

      expect(mockCaptureException).toHaveBeenCalledWith(
        error,
        expect.any(Function),
      );
      expect(result).toBe('mock-event-id');
    });

    it('should return undefined when disabled', () => {
      mockGetClient.mockReturnValue(undefined);

      const result = service.captureException(new Error('Test error'));

      expect(mockCaptureException).not.toHaveBeenCalled();
      expect(result).toBeUndefined();
    });
  });

  describe('captureMessage', () => {
    it('should capture message when enabled', () => {
      mockGetClient.mockReturnValue({});

      const result = service.captureMessage(
        'Horizon API down',
        'fatal',
        { endpoint: 'https://horizon.stellar.org' },
      );

      expect(mockCaptureMessage).toHaveBeenCalledWith(
        'Horizon API down',
        expect.any(Function),
      );
      expect(result).toBe('mock-event-id');
    });

    it('should return undefined when disabled', () => {
      mockGetClient.mockReturnValue(undefined);

      const result = service.captureMessage('test');

      expect(mockCaptureMessage).not.toHaveBeenCalled();
      expect(result).toBeUndefined();
    });
  });

  describe('setUser', () => {
    it('should set user with wallet', () => {
      service.setUser({
        id: 'user-1',
        wallet: 'GAB...XYZ',
        username: 'alice',
      });

      expect(mockSetUser).toHaveBeenCalledWith({
        id: 'user-1',
        username: 'alice',
        wallet: 'GAB...XYZ',
      });
    });

    it('should set user without wallet', () => {
      service.setUser({ id: 'user-1' });

      expect(mockSetUser).toHaveBeenCalledWith({
        id: 'user-1',
        username: undefined,
      });
    });
  });

  describe('clearUser', () => {
    it('should clear user context', () => {
      service.clearUser();
      expect(mockSetUser).toHaveBeenCalledWith(null);
    });
  });

  describe('addBreadcrumb', () => {
    it('should add breadcrumb with data', () => {
      service.addBreadcrumb({
        category: 'stellar',
        message: 'Payment submitted',
        level: 'info',
        data: { txHash: 'abc123' },
      });

      expect(mockAddBreadcrumb).toHaveBeenCalledWith({
        category: 'stellar',
        message: 'Payment submitted',
        level: 'info',
        data: { txHash: 'abc123' },
      });
    });

    it('should default level to info', () => {
      service.addBreadcrumb({
        category: 'stellar',
        message: 'Connected',
      });

      expect(mockAddBreadcrumb).toHaveBeenCalledWith(
        expect.objectContaining({ level: 'info' }),
      );
    });
  });

  describe('setTag', () => {
    it('should set tag', () => {
      service.setTag('network', 'testnet');
      expect(mockSetTag).toHaveBeenCalledWith('network', 'testnet');
    });
  });

  describe('setExtra', () => {
    it('should set extra data', () => {
      service.setExtra('contractId', 'C123');
      expect(mockSetExtra).toHaveBeenCalledWith('contractId', 'C123');
    });
  });
});

