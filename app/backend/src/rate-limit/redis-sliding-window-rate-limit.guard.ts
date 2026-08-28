import {
  CanActivate,
  ExecutionContext,
  HttpException,
  HttpStatus,
  Injectable,
} from "@nestjs/common";
import { Reflector } from "@nestjs/core";
import { parse } from "ipaddr.js";
import {
  RATE_LIMIT_GROUP_METADATA_KEY,
  RateLimitGroup,
  RateLimitKeyType,
} from "../config/rate-limit.config";
import { SlidingWindowRateLimiter } from "./sliding-window-rate-limiter.service";
import { MetricsService } from "../metrics/metrics.service";
import { throttlerConfig } from "../config/rate-limit.config";
import { RATE_LIMIT_API_KEY_MULTIPLIER } from "./sliding-window-rate-limiter.service";

type RequestWithRateLimitContext = Record<string, unknown> & {
  headers?: Record<string, string | string[] | undefined>;
  user?: { id?: string };
  apiKey?: { id?: string };
  ip?: string;
  route?: { path?: string };
  baseUrl?: string;
  path?: string;
  originalUrl?: string;
  method?: string;
  rateLimitContext?: {
    group: RateLimitGroup;
    keyType: RateLimitKeyType;
  };
};

/**
 * Global sliding-window rate-limit guard backed by Redis (with an in-memory
 * graceful-degradation fallback).
 *
 * Replaces the @nestjs/throttler guard. For every request it:
 *   - resolves the client identity (user_id -> api_key -> ip),
 *   - resolves the rate-limit group (webhooks/authenticated/public),
 *   - enforces a sliding window via SlidingWindowRateLimiter,
 *   - emits X-RateLimit-* headers and Retry-After on a 429.
 */
@Injectable()
export class RedisSlidingWindowRateLimitGuard implements CanActivate {
  constructor(
    private readonly reflector: Reflector,
    private readonly limiter: SlidingWindowRateLimiter,
    private readonly metricsService: MetricsService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const req = context
      .switchToHttp()
      .getRequest<RequestWithRateLimitContext>();
    const res = context.switchToHttp().getResponse<Record<string, unknown>>();

    // Allowlisted clients bypass rate limiting entirely.
    if (this.isClientInAllowlist(req)) {
      return true;
    }

    const group = this.resolveGroup(context, req);
    const identity = this.resolveIdentity(req);
    const isApiKey = identity.keyType === "api_key";
    const multiplier = isApiKey ? this.getApiKeyMultiplier(req) : 1;

    req.rateLimitContext = { group, keyType: identity.keyType };

    const decision = await this.limiter.consume(
      group,
      identity.value,
      multiplier,
    );

    if (!decision.allowed && decision.decision) {
      const retryAfterSeconds = Math.max(
        1,
        Math.ceil((decision.decision.resetAt - Date.now() / 1000)),
      );

      if (typeof res?.setHeader === "function") {
        res.setHeader("Retry-After", String(retryAfterSeconds));
        res.setHeader("X-RateLimit-Limit", String(decision.decision.limit));
        res.setHeader("X-RateLimit-Remaining", "0");
        res.setHeader(
          "X-RateLimit-Reset",
          String(decision.decision.resetAt),
        );
      }

      const routePath =
        req.route?.path ?? req.path ?? req.originalUrl ?? "unknown";

      this.metricsService.recordRateLimitedRequest(
        req.method ?? "unknown",
        routePath,
        group,
        identity.keyType,
      );

      throw new HttpException(
        {
          code: "RATE_LIMIT_EXCEEDED",
          message: `Too many requests. Retry after ${retryAfterSeconds} seconds.`,
          retryAfterSeconds,
        },
        HttpStatus.TOO_MANY_REQUESTS,
      );
    }

    // Emit rate-limit headers on successful responses.
    if (decision.decision && typeof res?.setHeader === "function") {
      res.setHeader("X-RateLimit-Limit", String(decision.decision.limit));
      res.setHeader(
        "X-RateLimit-Remaining",
        String(decision.decision.remaining),
      );
      res.setHeader(
        "X-RateLimit-Reset",
        String(decision.decision.resetAt),
      );
    }

    return true;
  }

  private isIpInAllowlist(ip: string): boolean {
    if (!throttlerConfig.allowlist.cidrs.length) return false;
    try {
      const clientIp = parse(ip);
      for (const cidr of throttlerConfig.allowlist.cidrs) {
        if (cidr.includes("/")) {
          const [range, prefix] = cidr.split("/");
          if (parse(range).match(clientIp, parseInt(prefix, 10))) return true;
        } else if (ip === cidr) {
          return true;
        }
      }
    } catch {
      return false;
    }
    return false;
  }

  private isClientInAllowlist(req: RequestWithRateLimitContext): boolean {
    const userId = this.getUserId(req);
    if (userId && throttlerConfig.allowlist.userIds.includes(userId)) {
      return true;
    }

    const apiKeyValue = this.getApiKeyValue(req);
    if (
      apiKeyValue &&
      throttlerConfig.allowlist.apiKeys.includes(apiKeyValue)
    ) {
      return true;
    }

    const ip = this.getIp(req);
    return ip !== "unknown" && this.isIpInAllowlist(ip);
  }

  private resolveGroup(
    context: ExecutionContext,
    req: RequestWithRateLimitContext,
  ): RateLimitGroup {
    const metadataGroup = this.reflector.getAllAndOverride<RateLimitGroup>(
      RATE_LIMIT_GROUP_METADATA_KEY,
      [context.getHandler(), context.getClass()],
    );
    if (metadataGroup) return metadataGroup;

    const path =
      `${req.baseUrl ?? ""}${req.route?.path ?? req.path ?? req.originalUrl ?? ""}`.toLowerCase();
    if (path.startsWith("/webhooks") || path.includes("/webhooks/")) {
      return "webhooks";
    }

    if (this.getUserId(req) || this.getApiKeyValue(req)) {
      return "authenticated";
    }

    return "public";
  }

  private resolveIdentity(req: RequestWithRateLimitContext): {
    keyType: RateLimitKeyType;
    value: string;
  } {
    const ip = this.getIp(req);

    for (const keyType of throttlerConfig.keyOrder) {
      if (keyType === "user_id") {
        const userId = this.getUserId(req);
        if (userId) return { keyType, value: userId };
      }
      if (keyType === "api_key") {
        const apiKey = this.getApiKeyValue(req);
        if (apiKey) return { keyType, value: apiKey };
      }
      if (keyType === "ip" && ip) {
        return { keyType, value: ip };
      }
    }

    return { keyType: "ip", value: ip || "unknown" };
  }

  /**
   * API keys may receive a configurable multiplier on their rate limits.
   */
  private getApiKeyMultiplier(req: RequestWithRateLimitContext): number {
    // Trusted (allowlisted) keys already bypass the limiter; any key that
    // reaches this point is a regular API key, so apply the configured
    // multiplier.
    void req;
    const multiplier = RATE_LIMIT_API_KEY_MULTIPLIER;
    return multiplier > 0 ? multiplier : 1;
  }

  private getUserId(req: RequestWithRateLimitContext): string | undefined {
    const user = req.user;
    if (user?.id && typeof user.id === "string") return user.id;

    const userId = req["userId"];
    if (typeof userId === "string" && userId.length > 0) return userId;

    const header = req.headers?.["x-user-id"];
    if (typeof header === "string" && header.length > 0) return header;

    return undefined;
  }

  private getApiKeyValue(req: RequestWithRateLimitContext): string | undefined {
    const apiKeyId = req.apiKey?.id;
    if (apiKeyId && typeof apiKeyId === "string") return apiKeyId;

    const header = req.headers?.["x-api-key"];
    if (typeof header === "string" && header.length > 0) return header;

    return undefined;
  }

  private getIp(req: RequestWithRateLimitContext): string {
    const forwardedFor = req.headers?.["x-forwarded-for"];
    if (typeof forwardedFor === "string" && forwardedFor.length > 0) {
      return forwardedFor.split(",")[0].trim();
    }
    return req.ip ?? "unknown";
  }
}
