import { Test, TestingModule } from '@nestjs/testing';
import { SearchController } from './search.controller';
import { SearchService } from './search.service';
import { UsernamesService } from '../usernames/usernames.service';
import { MarketplaceService } from '../marketplace/marketplace.service';
import { SupabaseService } from '../supabase/supabase.service';
import { BadRequestException } from '@nestjs/common';

describe('SearchController & SearchService', () => {
  let controller: SearchController;
  let service: SearchService;

  const mockUsernamesService = {
    searchPublicUsernames: jest.fn(),
  };

  const mockMarketplaceService = {
    getActiveListings: jest.fn(),
  };

  const mockSupabaseService = {};

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [SearchController],
      providers: [
        SearchService,
        { provide: UsernamesService, useValue: mockUsernamesService },
        { provide: MarketplaceService, useValue: mockMarketplaceService },
        { provide: SupabaseService, useValue: mockSupabaseService },
      ],
    }).compile();

    controller = module.get<SearchController>(SearchController);
    service = module.get<SearchService>(SearchService);
    jest.clearAllMocks();
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
    expect(service).toBeDefined();
  });

  describe('unifiedSearch', () => {
    it('returns mixed profile and listing search results', async () => {
      mockUsernamesService.searchPublicUsernames.mockResolvedValueOnce({
        data: [
          {
            id: 'p1',
            username: 'alice',
            public_key: 'GAAAAA1111',
            created_at: '2026-01-01T00:00:00Z',
            similarity_score: 95,
          },
        ],
      });

      mockMarketplaceService.getActiveListings.mockResolvedValueOnce({
        listings: [
          {
            id: 'l1',
            username: 'alice_premium',
            seller_public_key: 'GBBBBB2222',
            asking_price: 5000,
            status: 'active',
            category: 'og',
            created_at: '2026-01-02T00:00:00Z',
          },
        ],
      });

      const res = await controller.search({ q: 'alice', limit: 10, type: 'all' });

      expect(res.query).toBe('alice');
      expect(res.profiles).toHaveLength(1);
      expect(res.profiles[0].username).toBe('alice');
      expect(res.listings).toHaveLength(1);
      expect(res.listings[0].username).toBe('alice_premium');
      expect(res.totalProfiles).toBe(1);
      expect(res.totalListings).toBe(1);
    });

    it('provides typo suggestion (didYouMean) for misspellings with no exact matches', async () => {
      mockUsernamesService.searchPublicUsernames.mockResolvedValueOnce({
        data: [],
      });
      mockMarketplaceService.getActiveListings.mockResolvedValueOnce({
        listings: [],
      });

      const res = await controller.search({ q: 'alise' });

      expect(res.query).toBe('alise');
      expect(res.profiles).toHaveLength(0);
      expect(res.listings).toHaveLength(0);
      expect(res.didYouMean).toBe('alice');
    });

    it('throws BadRequestException for query shorter than 2 characters', async () => {
      await expect(controller.search({ q: 'a' })).rejects.toThrow(BadRequestException);
    });
  });
});
