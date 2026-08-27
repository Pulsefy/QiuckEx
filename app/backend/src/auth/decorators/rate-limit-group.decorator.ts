import { SetMetadata, Type } from "@nestjs/common";
import {
  RATE_LIMIT_GROUP_METADATA_KEY,
  RateLimitGroup,
} from "../../config/rate-limit.config";

export const DEFAULT_RATE_LIMIT_GROUP = "public-read" as RateLimitGroup;

export const RateLimitGroupTag = (group: RateLimitGroup = DEFAULT_RATE_LIMIT_GROUP) =>
  SetMetadata(RATE_LIMIT_GROUP_METADATA_KEY, group);

/**
 * Class-level decorator that applies the given rate limit group to all methods
 * of the controller. This ensures every endpoint within a controller is
 * assigned a named tier without individually tagging each handler.
 */
export const RateLimitGroupForAll = (group: RateLimitGroup = DEFAULT_RATE_LIMIT_GROUP) => (target: Type<any>) => {
  for (const propertyName of Object.getOwnPropertyNames(target.prototype)) {
    if (propertyName === "constructor") continue;
    const descriptor = Object.getOwnPropertyDescriptor(target.prototype, propertyName);
    if (descriptor && typeof descriptor.value === "function") {
      SetMetadata(RATE_LIMIT_GROUP_METADATA_KEY, group)(target.prototype, propertyName, descriptor);
    }
  }
  return target;
};
