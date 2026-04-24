import { SetMetadata } from "@nestjs/common";
import {
  RATE_LIMIT_GROUP_METADATA_KEY,
  RateLimitGroup,
} from "../../config/rate-limit.config";

export const RateLimitGroupTag = (group: RateLimitGroup) =>
  SetMetadata(RATE_LIMIT_GROUP_METADATA_KEY, group);
