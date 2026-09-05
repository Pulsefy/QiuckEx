import { SetMetadata, Type } from "@nestjs/common";
import {
  RATE_LIMIT_GROUP_METADATA_KEY,
  RateLimitGroup,
} from "../../config/rate-limit.config";

export const DEFAULT_RATE_LIMIT_GROUP = "public-read" as RateLimitGroup;

export const RateLimitGroupTag = (
  group: RateLimitGroup = DEFAULT_RATE_LIMIT_GROUP,
) true;
