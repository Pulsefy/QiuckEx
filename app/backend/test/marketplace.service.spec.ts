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
});
