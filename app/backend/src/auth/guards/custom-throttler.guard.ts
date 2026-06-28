import { ExecutionContext, Injectable, Inject, Logger } from "@nestjs/common";
import { Reflector } from "@nestjs/core";
import {
  ThrottlerException,
  ThrottlerGuard,
  ThrottlerRequest,
} from "@nestjs/throttler";
import {
  RATE_LIMIT_GROUP_METADATA_KEY,
  RateLimitAllowlist,
  RateLimitGroup,
  RateLimitKeyType,
  rateLimitAllowlist,
  THROTTLER_BURST_NAME,
  throttlerConfig,
} from "../../config/rate-limit.config";
import { MetricsService } from "../../metrics/metrics.service";

type AllowlistMatch = { matchedBy: "ip" | "api_key" } | { matchedBy: null };

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
  /** Set once an allowlist bypass has been audited, to avoid double-logging. */
  rateLimitAllowlistAudited?: boolean;
};

@Injectable()
export class CustomThrottlerGuard extends ThrottlerGuard {
  @Inject(MetricsService)
  private readonly metricsService: MetricsService;

  protected readonly reflector = new Reflector();

  private readonly logger = new Logger(CustomThrottlerGuard.name);

  protected async handleRequest(
    requestProps: ThrottlerRequest,
  ): Promise<boolean> {
    const { context, throttler } = requestProps;
    const req = context
      .switchToHttp()
      .getRequest<RequestWithRateLimitContext>();

    // Allowlisted callers (CI and trusted contributors on testnet) bypass
    // throttling entirely. Every bypass is logged and metered so the allowlist
    // stays auditable.
    const allowlistMatch = this.matchAllowlist(req);
    if (allowlistMatch.matchedBy !== null) {
      this.auditAllowlistBypass(req, allowlistMatch.matchedBy);
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
        const retryAfterSeconds = Math.ceil(windowConfig.ttlMs / 1000);
        const response = context
          .switchToHttp()
          .getResponse<Record<string, unknown>>();

        if (typeof response?.setHeader === "function") {
          response.setHeader("Retry-After", retryAfterSeconds.toString());
        }

        const method = req.method ?? "unknown";
        const routePath =
          req.route?.path ?? req.path ?? req.originalUrl ?? "unknown";
        const keyType = req.rateLimitContext.keyType;

        this.metricsService.recordRateLimitedRequest(
          method,
          routePath,
          group,
          keyType,
        );

        this.logger.warn(
          `Rate limit exceeded: ${method} ${routePath} ` +
            `[group=${group} key_type=${keyType} retry_after=${retryAfterSeconds}s]`,
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

  /**
   * Resolves the active allowlist. Indirection keeps the guard testable without
   * mutating process state.
   */
  protected getAllowlist(): RateLimitAllowlist {
    return rateLimitAllowlist;
  }

  /**
   * Returns how the request matched the allowlist, if at all. API keys are
   * checked before IPs so a trusted token wins over a shared egress IP.
   */
  private matchAllowlist(req: RequestWithRateLimitContext): AllowlistMatch {
    const allowlist = this.getAllowlist();

    const apiKey = this.getApiKeyValue(req);
    if (apiKey && allowlist.apiKeys.includes(apiKey)) {
      return { matchedBy: "api_key" };
    }

    const ip = this.getIp(req);
    if (ip && ip !== "unknown" && allowlist.ips.includes(ip)) {
      return { matchedBy: "ip" };
    }

    return { matchedBy: null };
  }

  /** Logs and meters an allowlist bypass exactly once per request. */
  private auditAllowlistBypass(
    req: RequestWithRateLimitContext,
    matchedBy: "ip" | "api_key",
  ): void {
    if (req.rateLimitAllowlistAudited) {
      return;
    }
    req.rateLimitAllowlistAudited = true;

    const method = req.method ?? "unknown";
    const routePath =
      req.route?.path ?? req.path ?? req.originalUrl ?? "unknown";

    this.metricsService.recordRateLimitAllowlistBypass(
      method,
      routePath,
      matchedBy,
    );

    const principal =
      matchedBy === "api_key"
        ? `api_key=${this.redactSecret(this.getApiKeyValue(req))}`
        : `ip=${this.getIp(req)}`;

    this.logger.log(
      `Rate limit bypassed via allowlist: ${method} ${routePath} ` +
        `[matched_by=${matchedBy} ${principal}]`,
    );
  }

  /** Redacts a secret for safe logging, keeping only a short identifying prefix. */
  private redactSecret(value?: string): string {
    if (!value) return "unknown";
    if (value.length <= 4) return "****";
    return `${value.slice(0, 4)}****`;
  }
}
