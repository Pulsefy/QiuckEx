export enum MarketplaceErrorCode {
  LISTING_NOT_FOUND = 'LISTING_NOT_FOUND',
  BID_NOT_FOUND = 'BID_NOT_FOUND',
  LISTING_NOT_ACTIVE = 'LISTING_NOT_ACTIVE',
  BID_NOT_PENDING = 'BID_NOT_PENDING',
  UNAUTHORIZED = 'MARKETPLACE_UNAUTHORIZED',
  USERNAME_NOT_OWNED = 'USERNAME_NOT_OWNED',
  ALREADY_LISTED = 'USERNAME_ALREADY_LISTED',
  SELF_BID = 'MARKETPLACE_SELF_BID',
  INVALID_PRICE = 'MARKETPLACE_INVALID_PRICE',
}

export class MarketplaceError extends Error {
  constructor(
    public readonly code: MarketplaceErrorCode,
    message: string,
  ) {
    super(message);
    this.name = 'MarketplaceError';
  }
}
