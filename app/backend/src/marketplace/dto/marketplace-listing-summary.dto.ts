import { MarketplaceListingSummary } from '../marketplace-listing-query';

export type MarketplaceListingSummaryDto = MarketplaceListingSummary;

export type GetMarketplaceListingsResponseDto = {
  listings: MarketplaceListingSummaryDto[];
  total: number;
  next_cursor: string | null;
  has_more: boolean;
};
