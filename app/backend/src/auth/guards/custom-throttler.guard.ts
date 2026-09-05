import { ExecutionContext, Injectable, Inject, HttpException, HttpStatus } from "@nestjs/common";	
import { Reflector } from "@nestjs/core";
import {
  ThrottlerException,
  ThrottlerGuard,
  ThrottlerRequest,
} from "@nestjs/throttler";
import { parse } from "ipaddr.js";
import {
  RATE_LIMIT_GROUP_METADATA_KEY,
  RateLimitGroup,
  RateLimitKeyType,
  THROTTLER_BURST_NAME,
  throttlerConfig,
} from "../../config/rate-limit.config";
import { MetricsService } from "../../metrics/metrics.service";

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

@Injectable()
export class CustomThrottlerGuard extends ThrottlerGuard {
  @Inject(MetricsService)
  private readonly metricsService: MetricsService;

  protected readonly reflector = new Reflector();

  private isIpInAllowlist(ip: string): boolean {
    if (!throttlerConfig.allowlist.cidrs.length) return false;
    
    try {
      const clientIp = parse(ip);
      
      for (const cidr of throttlerConfig.allowlist.cidrs) {
        if (cidr.includes('/')) {
          const [range, prefix] = cidr.split('/');
          if (parse(range).match(clientIp, parseInt(prefix))) {
            return true;
          }
        } else if (ip === cidr) {
          return true;
        }
      }
    } catch (e) {
      // If IP parsing fails, assume not in allowlist
      return false;
    }
    return false;
  }

  private isClientInAllowlist(req: RequestWithRateLimitContext): boolean {
    // Check if user is allowlisted
    const userId = this.getUserId(req);
    if (userId && throttlerConfig.allowlist.userIds.includes(userId)) {
      return true;
    }
    
    // Check if API key is allowlisted
    const apiKeyValue = this.getApiKeyValue(req);
    if (apiKeyValue && throttlerConfig.allowlist.apiKeys.includes(apiKeyValue)) {
      return true;
    }
    
    // Check if IP is allowlisted
    const ip = this.getIp(req);
    if (ip && this.isIpInAllowlist(ip)) {
      return true;
    }
    
    return false;
  }

  protected async handleRequest(
    requestProps: ThrottlerRequest,
  ): Promise<boolean> {
    const { context, throttler } = requestProps;
    const req = context
      .switchToHttp()
      .getRequest<RequestWithRateLimitContext>();

    // Skip rate limiting for allowlisted clients
    if (this.isClientInAllowlist(req)) {
      return true;
    }

    const group = this.resolveGroup(context, req);
    const window =
      throttler.name === THROTTLER_BURST_NAME ? "burst" : "sustained";
    const windowConfig = throttlerConfig.groups[group][window];

    req.rateLimitContext = {
      group,
      keyType: this.resolveIdentity(req).keyType,
    };

    try {
      return await super.handleRequest({
        ...requestProps,
        limit: windowConfig.limit,
        ttl: windowConfig.ttlMs,
        throttler: {
          ...throttler,
          limit: windowConfig.limit,
          ttl: windowConfig.ttlMs,
        },
      });
    } catch (error) {
      if (error instanceof ThrottlerException) {
        const retryBackSeconds = Math.ceil(windowConfig.ttlMs / 1000);
        const response = context
          .switchToHttp()
          .getResponse<Record<string, unknown>>();

        if (typeof response?.setHeader === "function") {
          response.setHeader("Retry-After", retryBackSeconds.toString());
        }

        const method = req.method ?? "unknown";
        const routePath = req.route?.path ?? req.path ?? req.originalUrl ?? "unknown";

        this.metricsService.recordRateLimitedRequest(
          method,
          routePath,
          group,
          req.rateLimitContext.keyType,
        );

        throw new HttpException(
          {
            statusCode: HttpStatus.TOO_MANY_REQUESTS,
            message: "Too Many Requests",
            error: "ThrottlerException",
            retryAfter: retryBackSeconds,
          },
          HttpStatus.TOO_MANY_REQUESTS,
        );
      }

      throw error;
    }
  }

  protected async getTracker(
    req: RequestWithRateLimitContext,
  ): Promise<string> {
    const identity = this.resolveIdentity(req);
    return `${identity.keyType}:${identity.value}`;
  }

  private resolveGroup(
    context: ExecutionContext,
    req: RequestWithRateLimitContext,
  ): RateLimitGroup {
    const metadataGroup = this.reflector.getAllAndOverride<RateLimitGroup>(
      RATE_LIMIT_GROUP_METADATA_KEY,
      [context.getHandler(), context.getClass()],
    );

    if (metadataGroup) {
      return metadataGroup;
    }

    const path =
      `${req.baseUrl ?? ""}${req.route?.path ?? req.path ?? req.originalUrl ?? ""}`.toLowerCase();

    // Webhooks have their own dedicated tier.
    if (path.startsWith("/webhooks") || path.includes("/webhooks/")) {
      return "webhooks";
    }

    // Map remaining public surface to named tiers per BE-116.
    const pathTier = this.resolveGroupFromPath(req.method ?? "GET", path);
    if (pathTier) {
      return pathTier;
    }

    // Keep existing fallback for authenticated/legacy routes.
    if (this.getUserId(req) || this.getApiKeyValue(req)) {
      return "authenticated";
    }

    return "public";
  }

  private resolveGroupFromPath(
    method: string,
    path: string,
  ): RateLimitGroup | undefined {
    // Endpoints that are cheap enumeration vectors get the strictest public-read tier.
    if (
      path.includes("/discovery") ||
      path.includes("/username") ||
      path.includes("/usernames") ||
      path.includes("/profile") ||
      path.includes("/profiles")
    ) {
      return "public-read" as RateLimitGroup;
    }

    // Marketplace queries and search endpoints use the search tier.
    if (
      path.includes("/marketplace") ||
      path.includes("/search")
    ) {
      return "search" as RateLimitGroup;
    }

    // Export requests (e.g., CSV/JSON exports) use the export tier.
    if (path.includes("/export") || path.endsWith("/exports")) {
      return "export" as RateLimitGroup;
    }

    // Any other non-GET request to a public endpoint is treated as a mutation.
    if (
      method !== "GET" &&
      method !== "HEAD" &&
      method !== "OPTIONS"
    ) {
      return "mutation" as RateLimitGroup;
    }

    return undefined;
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
