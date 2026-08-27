export const RATE_LIMITS = {
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
