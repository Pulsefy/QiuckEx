import { Test, TestingModule } from '@nestjs/testing';
import { UsernamesService } from '../usernames.service';
import { SupabaseService } from '../../supabase/supabase.service';
import { AppConfigService } from '../../config';
import {
  UsernameConflictError,
  UsernameLimitExceededError,
  UsernameValidationError,
} from '../errors';

describe('UsernamesService', () => {
  let service: UsernamesService;
  let supabaseGetClient: jest.Mock;
  let configMaxPerWallet: number | undefined;
  /** When set, countByPublicKey returns this count (for limit-exceeded test). */
  let mockCountForWallet: number;
  let sharedClient: { from: jest.Mock };

  const mockFrom = () => {
    const chain: Record<string, jest.Mock> = {
      insert: jest.fn().mockReturnThis(),
      select: jest.fn().mockReturnThis(),
      eq: jest.fn().mockReturnThis(),
      order: jest.fn().mockReturnThis(),
    };
    chain.insert.mockImplementation(() => Promise.resolve({ data: null, error: null }));
    chain.select.mockImplementation(() => chain);
    chain.eq.mockImplementation(() => chain);
    chain.order.mockImplementation(() => chain);
    return chain;
  };

  beforeEach(async () => {
    configMaxPerWallet = undefined;
    mockCountForWallet = 0;
    const usernamesChain = mockFrom();
    usernamesChain.insert.mockImplementation(() =>
      Promise.resolve({ data: null, error: null }),
    );
    let selectHeadMode = false;
    usernamesChain.select.mockImplementation((_args: string, opts?: { count?: string; head?: boolean }) => {
      selectHeadMode = opts?.head ?? false;
      return usernamesChain;
    });
    usernamesChain.eq.mockImplementation(() =>
      selectHeadMode
        ? Promise.resolve({
            count: mockCountForWallet,
            error: null,
          })
        : usernamesChain,
    );
    usernamesChain.order.mockImplementation(() =>
      Promise.resolve({ data: [], error: null }),
    );
    const from = jest.fn((table: string) =>
      table === 'usernames' ? usernamesChain : mockFrom(),
    );
    sharedClient = { from };
    supabaseGetClient = jest.fn().mockReturnValue(sharedClient);

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        UsernamesService,
        {
          provide: SupabaseService,
          useValue: { getClient: supabaseGetClient },
        },
        {
          provide: AppConfigService,
          useValue: {
            get maxUsernamesPerWallet(): number | undefined {
              return configMaxPerWallet;
            },
          },
        },
      ],
    }).compile();

    service = module.get<UsernamesService>(UsernamesService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('normalizeUsername', () => {
    it('returns lowercase username', () => {
      expect(service.normalizeUsername('Alice_123')).toBe('alice_123');
    });
    it('trims whitespace', () => {
      expect(service.normalizeUsername('  alice  ')).toBe('alice');
    });
  });

  describe('validateFormat', () => {
    it('accepts valid username', () => {
      expect(() => service.validateFormat('alice_123')).not.toThrow();
    });
    it('throws for too short', () => {
      expect(() => service.validateFormat('ab')).toThrow(UsernameValidationError);
    });
    it('throws for too long', () => {
      expect(() =>
        service.validateFormat('a'.repeat(33)),
      ).toThrow(UsernameValidationError);
    });
    it('throws for invalid characters', () => {
      expect(() => service.validateFormat('alice-123')).toThrow(
        UsernameValidationError,
      );
      expect(() => service.validateFormat('alice.bob')).toThrow(
        UsernameValidationError,
      );
    });
  });

  describe('create', () => {
    it('creates username and returns ok', async () => {
      const result = await service.create('alice_123', 'GBXGQ55JMQ4L2B6E7S8Y9Z0A1B2C3D4E5F6G7H8I7YWR');
      expect(result).toEqual({ ok: true });
      const chain = sharedClient.from('usernames');
      expect(sharedClient.from).toHaveBeenCalledWith('usernames');
      expect(chain.insert).toHaveBeenCalledWith({
        username: 'alice_123',
        public_key: 'GBXGQ55JMQ4L2B6E7S8Y9Z0A1B2C3D4E5F6G7H8I7YWR',
      });
    });

    it('normalizes username to lowercase before insert', async () => {
      await service.create('Alice_99', 'GBXGQ55JMQ4L2B6E7S8Y9Z0A1B2C3D4E5F6G7H8I7YWR');
      const chain = sharedClient.from('usernames');
      expect(chain.insert).toHaveBeenCalledWith(
        expect.objectContaining({ username: 'alice_99' }),
      );
    });

    it('throws UsernameConflictError on unique violation (23505)', async () => {
      const chain = sharedClient.from('usernames');
      chain.insert.mockResolvedValueOnce({
        data: null,
        error: { code: '23505', message: 'duplicate key' },
      });

      await expect(
        service.create('taken', 'GBXGQ55JMQ4L2B6E7S8Y9Z0A1B2C3D4E5F6G7H8I7YWR'),
      ).rejects.toThrow(UsernameConflictError);
    });

    it('conflict error message mentions username is already taken', async () => {
      const chain = sharedClient.from('usernames');
      chain.insert.mockResolvedValueOnce({
        data: null,
        error: { code: '23505', message: 'duplicate key' },
      });
      try {
        await service.create('taken', 'GBXGQ55JMQ4L2B6E7S8Y9Z0A1B2C3D4E5F6G7H8I7YWR');
      } catch (e) {
        expect(e).toBeInstanceOf(UsernameConflictError);
        expect((e as UsernameConflictError).username).toBe('taken');
        expect((e as Error).message).toMatch(/already taken/);
      }
    });

    it('throws UsernameValidationError for invalid format', async () => {
      await expect(
        service.create('ab', 'GBXGQ55JMQ4L2B6E7S8Y9Z0A1B2C3D4E5F6G7H8I7YWR'),
      ).rejects.toThrow(UsernameValidationError);
    });

    it('throws UsernameLimitExceededError when wallet at limit', async () => {
      configMaxPerWallet = 2;
      mockCountForWallet = 2;

      await expect(
        service.create('newuser', 'GBXGQ55JMQ4L2B6E7S8Y9Z0A1B2C3D4E5F6G7H8I7YWR'),
      ).rejects.toThrow(UsernameLimitExceededError);
    });
  });

  describe('listByPublicKey', () => {
    it('returns usernames for wallet', async () => {
      const rows = [
        {
          id: 'id1',
          username: 'alice',
          public_key: 'GBXGQ55JMQ4L2B6E7S8Y9Z0A1B2C3D4E5F6G7H8I7YWR',
          created_at: '2025-01-01T00:00:00Z',
        },
      ];
      const chain = sharedClient.from('usernames');
      chain.order.mockResolvedValueOnce({ data: rows, error: null });

      const result = await service.listByPublicKey(
        'GBXGQ55JMQ4L2B6E7S8Y9Z0A1B2C3D4E5F6G7H8I7YWR',
      );
      expect(result).toEqual(rows);
    });
  });
});
