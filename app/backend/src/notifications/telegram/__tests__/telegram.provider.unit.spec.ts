import { TelegramNotificationProvider } from '../telegram.provider';
import { TelegramBotService } from '../telegram-bot.service';
import { TelegramRepository } from '../telegram.repository';
import type { NotificationPreference, BaseNotificationPayload } from '../../types/notification.types';

const PUBLIC_KEY = 'GDQERHRWJYV7JHRP5V7DWJVI6Y5ABZP3YRH7DKYJRBEGJQKE6IQEOSY2';

// Define the type for the mapping object
interface TelegramUserMapping {
  telegramId: number;
  publicKey: string;
  isVerified: boolean;
  enabled: boolean;
  minAmountStroops?: bigint;
}

// Mock dependencies with proper typing
const mockTelegramBotService = {
  sendNotification: jest.fn(),
  verifyUser: jest.fn(),
  getBot: jest.fn(),
  onModuleInit: jest.fn(),
  onModuleDestroy: jest.fn(),
};

const mockTelegramRepository = {
  findByPublicKey: jest.fn(),
  updateLastNotification: jest.fn(),
  logNotification: jest.fn(),
  findByTelegramId: jest.fn(),
  upsertMapping: jest.fn(),
  markAsVerified: jest.fn(),
  setEnabled: jest.fn(),
  setMinAmount: jest.fn(),
  deleteMapping: jest.fn(),
  getEnabledMappings: jest.fn(),
};

function makePreference(
  overrides: Partial<NotificationPreference> = {},
): NotificationPreference {
  return {
    id: 'pref-1',
    publicKey: PUBLIC_KEY,
    channel: 'telegram',
    events: null,
    minAmountStroops: 0n,
    enabled: true,
    ...overrides,
  };
}

function makePayload(
  overrides: Partial<BaseNotificationPayload> = {},
): BaseNotificationPayload {
  return {
    eventType: 'payment.received',
    eventId: 'tx-hash-123',
    recipientPublicKey: PUBLIC_KEY,
    title: 'Payment Received',
    body: 'You received 10 XLM',
    occurredAt: new Date().toISOString(),
    amountStroops: 100_000_000n, // 10 XLM
    ...overrides,
  };
}

describe('TelegramNotificationProvider', () => {
  let provider: TelegramNotificationProvider;

  beforeEach(() => {
    jest.clearAllMocks();

    // Create the provider with mocked dependencies
    provider = new TelegramNotificationProvider(
      mockTelegramBotService as unknown as TelegramBotService,
      mockTelegramRepository as unknown as TelegramRepository
    );
  });

  describe('send', () => {
    it('sends notification to verified Telegram user', async () => {
      const mapping: TelegramUserMapping = {
        telegramId: 123456789,
        publicKey: PUBLIC_KEY,
        isVerified: true,
        enabled: true,
        minAmountStroops: 0n,
      };

      mockTelegramRepository.findByPublicKey.mockResolvedValue(mapping);
      mockTelegramBotService.sendNotification.mockResolvedValue(999);

      const pref = makePreference();
      const payload = makePayload();

      const result = await provider.send(pref, payload);

      expect(mockTelegramRepository.findByPublicKey).toHaveBeenCalledWith(PUBLIC_KEY);
      expect(mockTelegramBotService.sendNotification).toHaveBeenCalledWith(
        123456789,
        'Payment Received',
        expect.stringContaining('You received 10 XLM'),
        undefined,
      );
      expect(mockTelegramRepository.updateLastNotification).toHaveBeenCalledWith(123456789);
      expect(mockTelegramRepository.logNotification).toHaveBeenCalledWith(
        expect.objectContaining({
          telegramId: 123456789,
          status: 'sent',
          telegramMessageId: 999,
        }),
      );
      expect(result.messageId).toBe('999');
    });

    it('throws error when no Telegram mapping found', async () => {
      mockTelegramRepository.findByPublicKey.mockResolvedValue(null);

      const pref = makePreference();
      const payload = makePayload();

      await expect(provider.send(pref, payload)).rejects.toThrow(
        `No Telegram mapping found for public key ${PUBLIC_KEY}`,
      );
    });

    it('throws error when Telegram account is not verified', async () => {
      const mapping: TelegramUserMapping = {
        telegramId: 123456789,
        publicKey: PUBLIC_KEY,
        isVerified: false,
        enabled: true,
      };

      mockTelegramRepository.findByPublicKey.mockResolvedValue(mapping);

      const pref = makePreference();
      const payload = makePayload();

      await expect(provider.send(pref, payload)).rejects.toThrow(
        `Telegram account for ${PUBLIC_KEY} is not verified`,
      );
    });

    it('skips notification when notifications are disabled', async () => {
      const mapping: TelegramUserMapping = {
        telegramId: 123456789,
        publicKey: PUBLIC_KEY,
        isVerified: true,
        enabled: false,
        minAmountStroops: 0n,
      };

      mockTelegramRepository.findByPublicKey.mockResolvedValue(mapping);

      const pref = makePreference();
      const payload = makePayload();

      const result = await provider.send(pref, payload);

      expect(mockTelegramBotService.sendNotification).not.toHaveBeenCalled();
      expect(result.messageId).toBeUndefined();
    });

    it('skips notification when amount is below threshold', async () => {
      const mapping: TelegramUserMapping = {
        telegramId: 123456789,
        publicKey: PUBLIC_KEY,
        isVerified: true,
        enabled: true,
        minAmountStroops: 100_000_000n, // 10 XLM
      };

      mockTelegramRepository.findByPublicKey.mockResolvedValue(mapping);

      const pref = makePreference();
      const payload = makePayload({ amountStroops: 50_000_000n }); // 5 XLM

      const result = await provider.send(pref, payload);

      expect(mockTelegramBotService.sendNotification).not.toHaveBeenCalled();
      expect(result.messageId).toBeUndefined();
    });

    it('formats message with transaction details', async () => {
      const mapping: TelegramUserMapping = {
        telegramId: 123456789,
        publicKey: PUBLIC_KEY,
        isVerified: true,
        enabled: true,
        minAmountStroops: 0n,
      };

      mockTelegramRepository.findByPublicKey.mockResolvedValue(mapping);
      mockTelegramBotService.sendNotification.mockResolvedValue(999);

      const pref = makePreference();
      const payload = makePayload({
        metadata: {
          txHash: 'abc123def456',
          sender: 'GABC123DEF456',
        },
      });

      await provider.send(pref, payload);

      expect(mockTelegramBotService.sendNotification).toHaveBeenCalledWith(
        123456789,
        expect.any(String),
        expect.stringContaining('Transaction: `abc123de...`'),
        expect.objectContaining({
          txHash: 'abc123def456',
          sender: 'GABC123DEF456',
        }),
      );
    });
  });
});