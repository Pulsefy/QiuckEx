import { Test, TestingModule } from "@nestjs/testing";
import { MarketplaceService } from "../src/marketplace/marketplace.service";
import { SupabaseService } from "../src/supabase/supabase.service";
import {
  MarketplaceListing,
  MarketplaceBid,
} from "../src/supabase/supabase.service";
import { MarketplaceError, MarketplaceErrorCode } from "../src/marketplace/errors";
import { UsernamesService } from "../src/usernames/usernames.service";

describe("MarketplaceService", () => {
  let service: MarketplaceService;
  let supabaseMock: Partial<SupabaseService>;
  let usernamesMock: Partial<UsernamesService>;

  const mockListing: MarketplaceListing = {
    id: "listing-1",
    username: "nova",
    seller_public_key: "GSELLER1234567890SELLER1234567890SELLER12",
    asking_price: 100,
    status: "active",
    created_at: "2026-07-01T12:00:00.000Z",
    updated_at: "2026-07-01T12:00:00.000Z",
    sold_at: null,
    buyer_public_key: null,
    final_price: null,
  };

  const mockBids: MarketplaceBid[] = [
    {
      id: "b1",
      listing_id: "listing-1",
      bidder_public_key: "GBIDDER1",
      bid_amount: 120,
      status: "pending",
      created_at: "2026-07-02T12:00:00.000Z",
      updated_at: "2026-07-02T12:00:00.000Z",
    },
    {
      id: "b2",
      listing_id: "listing-1",
      bidder_public_key: "GBIDDER2",
      bid_amount: 180,
      status: "rejected",
      created_at: "2026-07-02T13:00:00.000Z",
      updated_at: "2026-07-02T13:00:00.000Z",
    },
  ];

  const mockBidPage = {
    bids: mockBids,
  };

  beforeEach(async () => {
    supabaseMock = {
      getListingById: jest.fn().mockResolvedValue(mockListing),
      getBidsByListingIdPaginated: jest.fn().mockResolvedValue(mockBidPage),
      queryActiveListings: jest.fn().mockResolvedValue({
        listings: [mockListing],
        next_cursor: null,
        has_more: false,
        total: 1,
      }),
      getBidsForListingIds: jest.fn().mockResolvedValue(mockBids),
    };

    usernamesMock = {};

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        MarketplaceService,
        { provide: SupabaseService, useValue: supabaseMock as jest.Mocked<SupabaseService> },
        { provide: UsernamesService, useValue: usernamesMock as jest.Mocked<UsernamesService> },
      ],
    }).compile();

    service = module.get<MarketplaceService>(MarketplaceService);
  });

  describe("getListingDetail", () => {
    it("should return listing detail for active listing", async () => {
      const result = await service.getListingDetail("listing-1");

      expect(result.listing).toEqual(mockListing);
      expect(result.bids).toEqual(mockBids);
      expect(result.bid_summary).toEqual({
        total_bids: 2,
        pending_bids: 1,
        highest_bid: 120,
        lowest_bid: 120,
      });
      expect(result.seller).toEqual({
        public_key: mockListing.seller_public_key,
        display_key: "GSEL...ER12",
      });
      expect(result.state_hints.is_available).toBe(true);
      expect(result.state_hints.can_place_bid).toBe(true);
      expect(result.state_hints.can_cancel).toBe(false);
      expect(result.state_hints.can_accept_bids).toBe(false);
    });

    it("should return detail for seller viewer", async () => {
      const result = await service.getListingDetail(
        "listing-1",
        mockListing.seller_public_key,
      );

      expect(result.state_hints.can_place_bid).toBe(false);
      expect(result.state_hints.can_cancel).toBe(true);
      expect(result.state_hints.can_accept_bids).toBe(true);
    });

    it("should handle ended listing", async () => {
      const endedListing: MarketplaceListing = {
        id: "listing-ended-1",
        username: "nova",
        seller_public_key: "GSELLER1234567890SELLER1234567890SELLER12",
        asking_price: 100,
        status: "sold",
        created_at: "2026-07-01T12:00:00.000Z",
        updated_at: "2026-07-01T12:00:00.000Z",
        sold_at: "2026-07-02T12:00:00.000Z",
        buyer_public_key: null,
        final_price: 150,
      };

      (supabaseMock.getListingById as jest.Mock).mockResolvedValue(endedListing);
      (supabaseMock.getBidsByListingIdPaginated as jest.Mock).mockResolvedValue({
        bids: [],
      });

      const result = await service.getListingDetail("listing-ended-1");
      expect(result.listing.status).toBe("sold");
      expect(result.state_hints.can_place_bid).toBe(false);
      expect(result.state_hints.can_cancel).toBe(false);
      expect(result.state_hints.can_accept_bids).toBe(false);
      expect(result.state_hints.is_available).toBe(false);
      expect(result.state_hints.unavailable_reason).toBe(
        "This listing has been sold.",
      );
    });

    it("should handle cancelled listing", async () => {
      const cancelledListing: MarketplaceListing = {
        ...mockListing,
        status: "cancelled",
      };

      (supabaseMock.getListingById as jest.Mock).mockResolvedValue(cancelledListing);
      (supabaseMock.getBidsByListingIdPaginated as jest.Mock).mockResolvedValue({
        bids: [],
      });

      const result = await service.getListingDetail("listing-cancelled-1");
      expect(result.state_hints.is_available).toBe(false);
      expect(result.state_hints.can_place_bid).toBe(false);
      expect(result.state_hints.can_cancel).toBe(false);
      expect(result.state_hints.can_accept_bids).toBe(false);
      expect(result.state_hints.unavailable_reason).toBe(
        "This listing is no longer available.",
      );
    });

    it("should throw LISTING_NOT_FOUND for missing listing", async () => {
      (supabaseMock.getListingById as jest.Mock).mockResolvedValue(null);

      await expect(
        service.getListingDetail("missing-listing-id"),
      ).rejects.toThrow(MarketplaceError);

      await expect(
        service.getListingDetail("missing-listing-id"),
      ).rejects.toMatchObject({
        code: MarketplaceErrorCode.LISTING_NOT_FOUND,
      });
    });
  });

  describe("queryListings", () => {
    it("passes sort/filter/pagination params through to the repository", async () => {
      await service.queryListings({
        sort: "price_desc",
        min_price: 10,
        max_price: 500,
        username: "no",
        limit: 5,
        cursor: "some-cursor",
      });

      expect(supabaseMock.queryActiveListings).toHaveBeenCalledWith({
        limit: 5,
        cursor: "some-cursor",
        sortColumn: "asking_price",
        ascending: false,
        minPrice: 10,
        maxPrice: 500,
        username: "no",
      });
    });

    it("defaults to newest sort and no filters when none are given", async () => {
      await service.queryListings({});

      expect(supabaseMock.queryActiveListings).toHaveBeenCalledWith({
        limit: 20,
        cursor: null,
        sortColumn: "created_at",
        ascending: false,
        minPrice: undefined,
        maxPrice: undefined,
        username: undefined,
      });
    });

    it("attaches bid summary and current_price to each returned listing", async () => {
      const result = await service.queryListings({});

      expect(supabaseMock.getBidsForListingIds).toHaveBeenCalledWith(["listing-1"]);
      expect(result.total).toBe(1);
      expect(result.listings).toHaveLength(1);
      expect(result.listings[0].id).toBe("listing-1");
      expect(result.listings[0].current_price).toBe(120); // highest pending bid
      expect(result.listings[0].bid_summary).toEqual({
        total_bids: 2,
        pending_bids: 1,
        highest_bid: 120,
        lowest_bid: 120,
      });
      expect(result.listings[0].ends_at).toBe("2026-07-03T12:00:00.000Z"); // created_at + 48h
    });

    it("skips the bid lookup when the page has no listings", async () => {
      (supabaseMock.queryActiveListings as jest.Mock).mockResolvedValue({
        listings: [],
        next_cursor: null,
        has_more: false,
        total: 0,
      });

      const result = await service.queryListings({});

      expect(supabaseMock.getBidsForListingIds).toHaveBeenCalledWith([]);
      expect(result.listings).toEqual([]);
      expect(result.total).toBe(0);
    });

    it("rejects when min_price is greater than max_price", async () => {
      await expect(
        service.queryListings({ min_price: 500, max_price: 100 }),
      ).rejects.toMatchObject({
        code: MarketplaceErrorCode.INVALID_PRICE_RANGE,
      });

      expect(supabaseMock.queryActiveListings).not.toHaveBeenCalled();
    });

    it("allows min_price equal to max_price", async () => {
      await expect(
        service.queryListings({ min_price: 100, max_price: 100 }),
      ).resolves.toBeDefined();
    });
  });
});
