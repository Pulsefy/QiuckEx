export const LinkConstraints = {
  AMOUNT: {
    MIN: 0.0000001,
    MAX: 1000000,
    DECIMALS: 7,
  },
  MEMO: {
    MAX_LENGTH: 28,
    ALLOWED_TYPES: ['text', 'id', 'hash', 'return'] as const,
    DEFAULT_TYPE: 'text',
  },
  ASSET: {
    WHITELIST: [
      'XLM',
      'USDC',
      'AQUA',
      'yXLM',
    ] as const,
    DEFAULT: 'XLM',
  },
  LINK: {
    DEFAULT_EXPIRATION_DAYS: 30,
    MAX_EXPIRATION_DAYS: 365,
  },
} as const;

export type AssetCode = typeof LinkConstraints.ASSET.WHITELIST[number];
export type MemoType = typeof LinkConstraints.MEMO.ALLOWED_TYPES[number];
