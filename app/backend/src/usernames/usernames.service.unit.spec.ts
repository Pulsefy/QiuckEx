import { Test, TestingModule } from '@nestjs/testing';
import { UsernamesService } from './usernames.service';
import { SupabaseService } from '../supabase/supabase.service';
import { AppConfigService } from '../config';
import { DiscoveryCacheService } from './cache/discovery-cache.service';
import {
  UsernameConflictError,
  UsernameLimitExceededError,
  UsernameValidationError,
} from './errors';
import { SupabaseUniqueConstraintError } from '../supabase/supabase.errors';

describe('UsernamesService', () => {
  let service: UsernamesService;
  let configMaxPerWallet: number | undefined;

  const mockSupabaseService = {
    insertUsername: jest.fn(),
    countUsernamesByPublicKey: jest.fn(),
    listUsernamesByPublicKey: jest.fn(),
    searchPublicUsernames: jest.fn(),
    updateUsernameActivity: jest.fn(),
  };

  beforeEach(async () => {
    configMaxPerWallet = undefined;
    jest.clearAllMocks();

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        UsernamesService,
        {
          provide: SupabaseService,
          useValue: mockSupabaseService,
        },
        {
          provide: AppConfigService,
          useValue: {
            get maxUsernamesPerWallet(): number | undefined {
              return configMaxPerWallet;
            },
          },
        },
        {
          provide: DiscoveryCacheService,
          useValue: {
            getSearchResults: jest.fn(),
            setSearchResults: jest.fn(),
            getTrendingResults: jest.fn(),
            setTrendingResults: jest.fn(),
            getRecentlyActiveResults: jest.fn(),
            setRecentlyActiveResults: jest.fn(),
            invalidateSearchCache: jest.fn(),
            invalidateTrendingCache: jest.fn(),
            invalidateRecentlyActiveCache: jest.fn(),
            getStats: jest.fn(),
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
      mockSupabaseService.insertUsername.mockResolvedValueOnce(undefined);
      const result = await service.create('alice_123', 'GBXGQ55JMQ4L2B6E7S8Y9Z0A1B2C3D4E5F6G7H8I7YWR');
      expect(result).toEqual({ ok: true });
      expect(mockSupabaseService.insertUsername).toHaveBeenCalledWith(
        'alice_123',
        'GBXGQ55JMQ4L2B6E7S8Y9Z0A1B2C3D4E5F6G7H8I7YWR',
      );
    });

    it('normalizes username to lowercase before insert', async () => {
      mockSupabaseService.insertUsername.mockResolvedValueOnce(undefined);
      await service.create('Alice_99', 'GBXGQ55JMQ4L2B6E7S8Y9Z0A1B2C3D4E5F6G7H8I7YWR');
      expect(mockSupabaseService.insertUsername).toHaveBeenCalledWith(
        'alice_99',
        expect.any(String),
      );
    });

    it('throws UsernameConflictError on unique violation (SupabaseUniqueConstraintError)', async () => {
      mockSupabaseService.insertUsername.mockRejectedValueOnce(
        new SupabaseUniqueConstraintError('duplicate key')
      );

      await expect(
        service.create('taken', 'GBXGQ55JMQ4L2B6E7S8Y9Z0A1B2C3D4E5F6G7H8I7YWR'),
      ).rejects.toThrow(UsernameConflictError);
    });

    it('conflict error message mentions username is already taken', async () => {
      mockSupabaseService.insertUsername.mockRejectedValueOnce(
        new SupabaseUniqueConstraintError('duplicate key')
      );
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
      mockSupabaseService.countUsernamesByPublicKey.mockResolvedValueOnce(2);

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
      mockSupabaseService.listUsernamesByPublicKey.mockResolvedValueOnce(rows);

      const result = await service.listByPublicKey(
        'GBXGQ55JMQ4L2B6E7S8Y9Z0A1B2C3D4E5F6G7H8I7YWR',
      );
      expect(result).toEqual(rows);
    });
  });

  describe('searchPublicUsernames', () => {
    const rows = [
      {
        id: 'id-4',
        username: 'alice4',
        public_key: 'GAAA4',
        created_at: '2025-01-04T00:00:00.000Z',
        last_active_at: null,
        is_public: true,
      },
      {
        id: 'id-3',
        username: 'alice3',
        public_key: 'GAAA3',
        created_at: '2025-01-03T00:00:00.000Z',
        last_active_at: null,
        is_public: true,
      },
      {
        id: 'id-2',
        username: 'alice2',
        public_key: 'GAAA2',
        created_at: '2025-01-02T00:00:00.000Z',
        last_active_at: null,
        is_public: true,
      },
      {
        id: 'id-1',
        username: 'alice1',
        public_key: 'GAAA1',
        created_at: '2025-01-01T00:00:00.000Z',
        last_active_at: null,
        is_public: true,
      },
    ];

    it('returns first page with next_cursor and has_more=true', async () => {
      mockSupabaseService.searchPublicUsernames.mockResolvedValueOnce(rows.slice(0, 3));

      const result = await service.searchPublicUsernames('alice', 2);

      expect(result.data.map((r: { id: string }) => r.id)).toEqual(['id-4', 'id-3']);
      expect(result.has_more).toBe(true);
      expect(result.next_cursor).toBeTruthy();
      expect(mockSupabaseService.updateUsernameActivity).toHaveBeenCalledWith('alice4');
    });

    it('advances to next page when cursor is provided', async () => {
      mockSupabaseService.searchPublicUsernames.mockResolvedValueOnce(rows);
      const cursor = Buffer.from(
        JSON.stringify({ pk: '2025-01-03T00:00:00.000Z', id: 'id-3' }),
        'utf-8',
      ).toString('base64url');

      const result = await service.searchPublicUsernames('alice', 2, cursor);

      expect(result.data.map((r: { id: string }) => r.id)).toEqual(['id-2', 'id-1']);
      expect(result.has_more).toBe(false);
      expect(result.next_cursor).toBeNull();
      expect(mockSupabaseService.searchPublicUsernames).toHaveBeenCalledWith('alice', 100);
    });
  });
});
