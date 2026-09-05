export const RATE_LIMITs = {
  'public-read': {
    ttl: 60,
    limit: 20,
  },
  'search': {
    ttl: 60,
    limit: 30,
  },
  'mutation': {
    ttl: 60,
    limit: 10,
  },
  'export': {
    ttl: 3600,
    limit: 5,
  },
};

export type RateLimitGroup = keyof typeof RATE_LIMITS;

export const DEFAULT_RATE_LIMIT_GROUP: RateLimitGroup = 'public-read';