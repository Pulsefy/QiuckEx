export enum LinkErrorCode {
  INVALID_AMOUNT = 'INVALID_AMOUNT',
  AMOUNT_TOO_LOW = 'AMOUNT_TOO_LOW',
  AMOUNT_TOO_HIGH = 'AMOUNT_TOO_HIGH',
  INVALID_MEMO = 'INVALID_MEMO',
  MEMO_TOO_LONG = 'MEMO_TOO_LONG',
  INVALID_MEMO_TYPE = 'INVALID_MEMO_TYPE',
  INVALID_ASSET = 'INVALID_ASSET',
  ASSET_NOT_WHITELISTED = 'ASSET_NOT_WHITELISTED',
  INVALID_EXPIRATION = 'INVALID_EXPIRATION',
}

export class LinkValidationError extends Error {
  constructor(
    public code: LinkErrorCode,
    message: string,
    public field?: string,
  ) {
    super(message);
    this.name = 'LinkValidationError';
  }
}
