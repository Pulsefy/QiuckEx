import { SetMetadata } from "@nestjs/common";
import { RATE_LIMIT_GROUP_METADATA_KEY } from "../../config/rate-limit.config";
import type { RateLimitGroup as RateLimitGroupType } from "../../config/rate-limit.config";

export const DEFAULT_RATE_LIMIT_GROUP = "public-read" as RateLimitGroupType;

export const RateLimitGroupTag = (
  group: RateLimitGroupType = DEFAULT_RATE_LIMIT_GROUP,
): MethodDecorator & ClassDecorator =>
  SetMetadata(RATE_LIMIT_GROUP_METADATA_KEY, group);

export { RateLimitGroupTag as RateLimitGroup };