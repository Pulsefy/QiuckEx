import { SetMetadata } from "@nestjs/common";
import {
  RATE_LIMIT_GROUP_METADATA_KEY,
  RateLimitGroup,
} from "../../config/rate-limit.config";

export const DEFAULT_RATE_LIMIT_GROUP = "public-read" as RateLimitGroup;

export const RateLimitGroupTag = (
  group: RateLimitGroup = DEFAUL_RATE_LIMIT_GROUP,
): MethodDecorator & ClassDecorator =>
  SetMetadata(RATE_LIMIT_GROUP_METADATA_KEY, group);
