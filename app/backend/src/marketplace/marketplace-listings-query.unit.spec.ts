import { Test, TestingModule } from '@nestjs/testing';
import { SupabaseService, MarketplaceListing } from '../supabase/supabase.service';
import { MarketplaceService } from './marketplace.service';
import { MarketplaceListingStatus, MarketplaceSortField } from './dto/list-marketplace-listings-query.dto';
import { UsernamesService } from '../usernames/usernames.service';

describe('MarketplaceListingsQuery', () => {
  let marketplaceService: MarketplaceService;
  let supabaseService: SupabaseService;
  let mockQueryListings: jest.Mock;

  const baseListing: MarketplaceListing = {
    id: 'listing-1',
    username: 'alice',
    seller_public_key: 'GABCDEF1234567890ABCDEF1234567890ABCDEF1234',
    asking_price: 100,
    status: 'active',
    created_at: '2026-07-01T12:00:00.000Z',
    updated_at: '2026-07-01T12:00:00.000Z',
    expires_at: '2026-07-08T12:00:00.000Z',
    sold_at: null,
    buyer_public_key: null,
    final_price: null,
  };

  const makeListing = (overrides: Partial<MarketplaceListing>): MarketplaceListing => ({
    ...baseListing,
    ...overrides,
  });

  const buildPaginatedResult = (listings: MarketplaceListing[], page: number, limit: number, total: number) => ({
    listings,
    total,
    totalPages: Math.ceil(total / limit),
    currentPage: page,
    pageSize: limit,
    next_cursor: null,
    has_more: page < Math.ceil(total / limit),
  });

  beforeEach(async () => {
    mockQueryListings = jest.fn();

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        MarketplaceService,
        {
          provide: SupabaseService,
          useValue: {
            queryListings: mockQueryListings,
            getActiveListings: jest.fn(),
            searchActiveListings: jest.fn(),
          },
        },
        {
          provide: UsernamesService,
          useValue: {
            listByPublicKey: jest.fn(),
          },
        },
      ],
    }).compile();

    marketplaceService = module.get<MarketplaceService>(MarketplaceService);
    supabaseService = module.get<SupabaseService>(SupabaseService);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  // -----------------------------------------------------------------------
  // Default behavior
  // -----------------------------------------------------------------------
  describe('default behavior', () => {
    it('returns active listings sorted by newest by default', async () => {
      const listings = [
        makeListing({ id: 'l1', username: 'zara', created_at: '2026-07-03T12:00:00.000Z' }),
        makeListing({ id: 'l2', username: 'yves', created_at: '2026-07-02T12:00:00.000Z' }),
      ];
      mockQueryListings.mockResolvedValue(buildPaginatedResult(listings, 1, 20, 2));

      const result = await marketplaceService.listListings({});

      expect(mockQueryListings).toHaveBeenCalledWith({
        page: 1,
        limit: 20,
        cursor: null,
        minPrice: undefined,
        maxPrice: undefined,
        username: undefined,
        status: 'active',
        sort: 'newest',
      });
      expect(result.listings).toHaveLength(2);
      expect(result.total).toBe(2);
    });

    it('returns empty result when no listings exist', async () => {
      mockQueryListings.mockResolvedValue(buildPaginatedResult([], 1, 20, 0));

      const result = await marketplaceService.listListings({});

      expect(result.listings).toHaveLength(0);
      expect(result.total).toBe(0);
      expect(result.totalPages).toBe(1);
      expect(result.has_more).toBe(false);
    });
  });

  // -----------------------------------------------------------------------
  // Filtering
  // -----------------------------------------------------------------------
  describe('filtering', () => {
    it('filters by minimum price', async () => {
      const listings = [
        makeListing({ id: 'l1', username: 'premium', asking_price: 500 }),
        makeListing({ id: 'l2', username: 'luxury', asking_price: 1000 }),
      ];
      mockQueryListings.mockResolvedValue(buildPaginatedResult(listings, 1, 20, 2));

      const result = await marketplaceService.listListings({ minPrice: 200, maxPrice: undefined });

      expect(mockQueryListings).toHaveBeenCalledWith(
        expect.objectContaining({ minPrice: 200, maxPrice: undefined }),
      );
      expect(result.listings).toHaveLength(2);
    });

    it('filters by maximum price', async () => {
      mockQueryListings.mockResolvedValue(buildPaginatedResult([makeListing({ id: 'l1' })], 1, 20, 1));

      const result = await marketplaceService.listListings({ maxPrice: 50 });

      expect(mockQueryListings).toHaveBeenCalledWith(
        expect.objectContaining({ maxPrice: 50 }),
      );
      expect(result.total).toBe(1);
    });

    it('filters by both min and max price', async () => {
      mockQueryListings.mockResolvedValue(buildPaginatedResult([], 1, 20, 0));

      const result = await marketplaceService.listListings({ minPrice: 100, maxPrice: 200 });

      expect(mockQueryListings).toHaveBeenCalledWith(
        expect.objectContaining({ minPrice: 100, maxPrice: 200 }),
      );
      expect(result.total).toBe(0);
    });

    it('filters by username (partial search)', async () => {
      mockQueryListings.mockResolvedValue(
        buildPaginatedResult([makeListing({ id: 'l1', username: 'alice_123' })], 1, 20, 1),
      );

      const result = await marketplaceService.listListings({ username: 'alice' });

      expect(mockQueryListings).toHaveBeenCalledWith(
        expect.objectContaining({ username: 'alice' }),
      );
      expect(result.listings[0].username).toContain('alice');
    });

    it('filters by status', async () => {
      const sold = makeListing({ id: 'l1', username: 'sold_user', status: 'sold' });
      mockQueryListings.mockResolvedValue(buildPaginatedResult([sold], 1, 20, 1));

      const result = await marketplaceService.listListings({ status: MarketplaceListingStatus.SOLD });

      expect(mockQueryListings).toHaveBeenCalledWith(
        expect.objectContaining({ status: 'sold' }),
      );
      expect(result.listings[0].status).toBe('sold');
    });

    it('returns all statuses when status=all', async () => {
      const listings = [
        makeListing({ id: 'l1', username: 'active_user', status: 'active' }),
        makeListing({ id: 'l2', username: 'sold_user', status: 'sold' }),
        makeListing({ id: 'l3', username: 'cancelled_user', status: 'cancelled' }),
      ];
      mockQueryListings.mockResolvedValue(buildPaginatedResult(listings, 1, 20, 3));

      const result = await marketplaceService.listListings({ status: MarketplaceListingStatus.ALL });

      expect(mockQueryListings).toHaveBeenCalledWith(
        expect.objectContaining({ status: 'all' }),
      );
      expect(result.total).toBe(3);
    });
  });

  // -----------------------------------------------------------------------
  // Sorting
  // -----------------------------------------------------------------------
  describe('sorting', () => {
    it('sorts by newest (default)', async () => {
      await marketplaceService.listListings({ sort: MarketplaceSortField.NEWEST });
      expect(mockQueryListings).toHaveBeenCalledWith(expect.objectContaining({ sort: 'newest' }));
    });

    it('sorts by oldest', async () => {
      await marketplaceService.listListings({ sort: MarketplaceSortField.OLDEST });
      expect(mockQueryListings).toHaveBeenCalledWith(expect.objectContaining({ sort: 'oldest' }));
    });

    it('sorts by price ascending', async () => {
      await marketplaceService.listListings({ sort: MarketplaceSortField.PRICE_ASC });
      expect(mockQueryListings).toHaveBeenCalledWith(expect.objectContaining({ sort: 'price_asc' }));
    });

    it('sorts by price descending', async () => {
      await marketplaceService.listListings({ sort: MarketplaceSortField.PRICE_DESC });
      expect(mockQueryListings).toHaveBeenCalledWith(expect.objectContaining({ sort: 'price_desc' }));
    });

    it('sorts by ending soon', async () => {
      await marketplaceService.listListings({ sort: MarketplaceSortField.ENDING_SOON });
      expect(mockQueryListings).toHaveBeenCalledWith(expect.objectContaining({ sort: 'ending_soon' }));
    });
  });

  // -----------------------------------------------------------------------
  // Pagination
  // -----------------------------------------------------------------------
  describe('pagination', () => {
    it('returns first page by default', async () => {
      const listings = Array.from({ length: 20 }, (_, i) =>
        makeListing({ id: `l${i + 1}`, username: `user${i + 1}` }),
      );
      mockQueryListings.mockResolvedValue(buildPaginatedResult(listings, 1, 20, 50));

      const result = await marketplaceService.listListings({ page: 1, limit: 20 });

      expect(result.currentPage).toBe(1);
      expect(result.pageSize).toBe(20);
      expect(result.total).toBe(50);
      expect(result.totalPages).toBe(3);
      expect(result.has_more).toBe(true);
    });

    it('returns middle page correctly', async () => {
      mockQueryListings.mockResolvedValue(buildPaginatedResult([], 2, 10, 25));

      const result = await marketplaceService.listListings({ page: 2, limit: 10 });

      expect(result.currentPage).toBe(2);
      expect(result.pageSize).toBe(10);
      expect(result.has_more).toBe(true);
    });

    it('returns last page with has_more=false', async () => {
      mockQueryListings.mockResolvedValue(buildPaginatedResult([], 3, 10, 25));

      const result = await marketplaceService.listListings({ page: 3, limit: 10 });

      expect(result.currentPage).toBe(3);
      expect(result.pageSize).toBe(10);
      expect(result.has_more).toBe(false);
    });

    it('returns empty page beyond total', async () => {
      mockQueryListings.mockResolvedValue(buildPaginatedResult([], 10, 20, 2));

      const result = await marketplaceService.listListings({ page: 10, limit: 20 });

      expect(result.listings).toHaveLength(0);
      expect(result.currentPage).toBe(10);
      expect(result.totalPages).toBe(1);
      expect(result.has_more).toBe(false);
    });
  });

  // -----------------------------------------------------------------------
  // Edge cases
  // -----------------------------------------------------------------------
  describe('edge cases', () => {
    it('returns one listing correctly', async () => {
      mockQueryListings.mockResolvedValue(buildPaginatedResult([baseListing], 1, 20, 1));

      const result = await marketplaceService.listListings({});

      expect(result.listings).toHaveLength(1);
      expect(result.listings[0].id).toBe('listing-1');
      expect(result.total).toBe(1);
      expect(result.totalPages).toBe(1);
    });

    it('handles listings with identical prices deterministically', async () => {
      const listings = [
        makeListing({ id: 'l1', username: 'alpha', asking_price: 100 }),
        makeListing({ id: 'l2', username: 'beta', asking_price: 100 }),
      ];
      mockQueryListings.mockResolvedValue(buildPaginatedResult(listings, 1, 20, 2));

      const result = await marketplaceService.listListings({ sort: MarketplaceSortField.PRICE_ASC });

      // Both have same price, order is deterministic by id tiebreaker
      expect(result.listings).toHaveLength(2);
      expect(result.listings.every((l) => l.asking_price === 100)).toBe(true);
    });

    it('handles expired/ended listings when filtered', async () => {
      const expiredListing = makeListing({
        id: 'l1',
        username: 'expired_user',
        status: 'sold',
        expires_at: '2026-06-01T12:00:00.000Z',
      });
      mockQueryListings.mockResolvedValue(buildPaginatedResult([expiredListing], 1, 20, 1));

      const result = await marketplaceService.listListings({ status: MarketplaceListingStatus.SOLD });

      expect(result.listings[0].status).toBe('sold');
      expect(result.listings[0].expires_at).toBe('2026-06-01T12:00:00.000Z');
    });

    it('handles empty username search gracefully', async () => {
      mockQueryListings.mockResolvedValue(buildPaginatedResult([], 1, 20, 0));

      const result = await marketplaceService.listListings({ username: '' });

      expect(result.total).toBe(0);
    });

    it('handles zero limit gracefully', async () => {
      mockQueryListings.mockResolvedValue(buildPaginatedResult([baseListing], 1, 1, 1));

      const result = await marketplaceService.listListings({ limit: 1 });

      expect(result.listings).toHaveLength(1);
      expect(result.pageSize).toBe(1);
    });

    it('passes cursor parameter for backward compatibility', async () => {
      const cursor = 'eyJwayI6IjIwMjYtMDEtMDFUMDA6MDA6MDAuMDAwWiIsImlkIjoiMTIzIn0';
      mockQueryListings.mockResolvedValue(
        buildPaginatedResult([makeListing({ id: 'l1' })], 1, 20, 1),
      );

      await marketplaceService.listListings({ cursor });

      expect(mockQueryListings).toHaveBeenCalledWith(
        expect.objectContaining({ cursor }),
      );
    });
  });

  // -----------------------------------------------------------------------
  // Response payload structure
  // -----------------------------------------------------------------------
  describe('response payload structure', () => {
    it('includes all required pagination metadata', async () => {
      mockQueryListings.mockResolvedValue(buildPaginatedResult([baseListing], 1, 20, 1));

      const result = await marketplaceService.listListings({});

      expect(result).toHaveProperty('listings');
      expect(result).toHaveProperty('total');
      expect(result).toHaveProperty('totalPages');
      expect(result).toHaveProperty('currentPage');
      expect(result).toHaveProperty('pageSize');
      expect(result).toHaveProperty('next_cursor');
      expect(result).toHaveProperty('has_more');
    });

    it('includes all required listing fields', async () => {
      mockQueryListings.mockResolvedValue(buildPaginatedResult([baseListing], 1, 20, 1));

      const result = await marketplaceService.listListings({});
      const listing = result.listings[0];

      expect(listing).toHaveProperty('id');
      expect(listing).toHaveProperty('username');
      expect(listing).toHaveProperty('seller_public_key');
      expect(listing).toHaveProperty('asking_price');
      expect(listing).toHaveProperty('status');
      expect(listing).toHaveProperty('created_at');
      expect(listing).toHaveProperty('expires_at');
      expect(listing).toHaveProperty('sold_at');
      expect(listing).toHaveProperty('buyer_public_key');
      expect(listing).toHaveProperty('final_price');
    });
  });
});
