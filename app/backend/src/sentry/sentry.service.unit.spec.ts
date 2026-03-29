/* eslint-disable @typescript-eslint/no-explicit-any */
import { Test, TestingModule } from '@nestjs/testing';
import { SentryService } from './sentry.service';

// Mock the @sentry/nestjs module entirely
const mockGetClient = jest.fn();
const mockCaptureException = jest.fn().mockReturnValue('mock-event-id');
const mockCaptureMessage = jest.fn().mockReturnValue('mock-event-id');
const mockSetUser = jest.fn();
const mockAddBreadcrumb = jest.fn();
const mockSetTag = jest.fn();
const mockSetExtra = jest.fn();

jest.mock('@sentry/nestjs', () => ({
  getClient: mockGetClient,
  captureException: mockCaptureException,
  captureMessage: mockCaptureMessage,
  setUser: mockSetUser,
  addBreadcrumb: mockAddBreadcrumb,
  setTag: mockSetTag,
  setExtra: mockSetExtra,
}));

describe('SentryService', () => {
  let service: SentryService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [SentryService],
    }).compile();

    service = module.get<SentryService>(SentryService);
    jest.clearAllMocks();
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
    it('should capture exception when Sentry is enabled', () => {
      mockGetClient.mockReturnValue({});
      const error = new Error('Test error');
      const result = service.captureException(error, { orderId: '123' });
      expect(mockCaptureException).toHaveBeenCalledWith(
        error,
        expect.any(Function),
      );
      expect(result).toBe('mock-event-id');
    });

    it('should return undefined when Sentry is not enabled', () => {
      mockGetClient.mockReturnValue(undefined);
      const error = new Error('Test error');
      const result = service.captureException(error);
      expect(mockCaptureException).not.toHaveBeenCalled();
      expect(result).toBeUndefined();
    });
  });

  describe('captureMessage', () => {
    it('should capture message when Sentry is enabled', () => {
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

    it('should return undefined when Sentry is not enabled', () => {
      mockGetClient.mockReturnValue(undefined);
      const result = service.captureMessage('test');
      expect(mockCaptureMessage).not.toHaveBeenCalled();
      expect(result).toBeUndefined();
    });
  });

  describe('setUser', () => {
    it('should set user context with wallet', () => {
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

    it('should set user context without wallet', () => {
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
    it('should add a breadcrumb with custom data', () => {
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
    it('should set a tag on the scope', () => {
      service.setTag('network', 'testnet');
      expect(mockSetTag).toHaveBeenCalledWith('network', 'testnet');
    });
  });

  describe('setExtra', () => {
    it('should set extra data on the scope', () => {
      service.setExtra('contractId', 'C123');
      expect(mockSetExtra).toHaveBeenCalledWith('contractId', 'C123');
    });
  });
});
