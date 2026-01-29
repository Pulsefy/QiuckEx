import { RATE_LIMITS } from '../common/constants/rate-limit.constants';

export const throttlerConfig = {
  ttl: RATE_LIMITS.PUBLIC.ttl,
  limit: RATE_LIMITS.PUBLIC.limit,
};
