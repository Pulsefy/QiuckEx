import { ExecutionContext, Injectable, Inject } from "@nestjs/common";
import { Reflector } from "@nestjs/core";
import {
  ThrottlerException,
  ThrottlerGuard,
  ThrottlerRequest,
} from "@nestjs/throttler";
import { parse } from "ipaddr.js";
import type {
  RateLimitGroup,
  RateLimitKeyType,
  RateLimitTier,
} from "../../config/rate-limit.config";
import {
  RATE_LIMIT_GROUP_METADATA_KEY,
  RATE_LIMIT_TIER_METADATA_KEY,
  THROTTLER_BURST_NAME,
  throttlerConfig,
} from "../../config/rate-limit.config";
import { MetricsService } from "../../metrics/metrics.service";

type RequestWithRateLimitContext = Record<string, unknown> & {
  headers?: Record<string, string | string[] | undefined>;
  user?: { id?: string };
  apiKey?: { id?: string };
  ip?: string;
  socket?: { remoteAddress?: string };
  connection?: { remoteAddress?: string };
  route?: { path?: string };
  baseUrl?: string;
  path?: string;
  originalUrl?: string;
  method?: string;
  rateLimitContext?: {
    group?: RateLimitGroup;
    tier?: RateLimitTier;
    keyType: RateLimitKeyType;
  };
};

@injectable()
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
    
    // Check if IP is allowlisted (only trusted client IP is used)
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

    const window =
      throttler.name === THROTTLER_BURST_NAME ? "burst" : "sustained";
    const identity = this.resolveIdentity(req);

    let windowConfig: { limit: number; ttlMs: number };
    const tier = this.resolveTier(context);
    const group = this.resolveGroup(context, req);

    if (tier) {
      windowConfig = throttlerConfig.tiers[tier][window];
      req.rateLimitContext = {
        tier,
        keyType: identity.keyType,
      };
    } else {
      windowConfig = throttlerConfig.groups[group][window];
      req.rateLimitContext = {
        group,
        keyType: identity.keyType,
      };
    }

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
        const routePath = req.route?.path ?? req.path ?? req.originalUrl ?? "unknown";
        const entity = tier ?? group;

        this.metricsService.recordRateLimitedRequest(
          method,
          routePath,
          entity,
          req.rateLimitContext.keyType,
        );
      }

      throw error;
    }
  }

  private resolveTier(context: ExecutionContext): RateLimitTier | undefined {
    return this.reflector.getAllAndOverride<RateLimitTier>(
      RATE_LIMIT_TIER_METADATA_KEY,
      [context.getHandler(), context.getClass()],
    );
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

  /**
   * Resolve the client IP for rate-limiting and allowlist decisions.
   *
   * X-Forwarded-For is only trusted when the immediate peer (socket remote
   * address) is a configured trusted proxy. The header is walked from right to
   * left, skipping trusted proxies, and the first untrusted address is
   * returned. This prevents a client from spoofing an arbitrary value in the
   * header to obtain a fresh rate-limit bucket or to impersonate an
   * allowlisted IP.
   */
  private getIp(req: RequestWithRateLimitContext): string {
    const socketIp = this.getSocketIp(req);
    const trustedProxies = this.getTrustedProxies();

    // Direct internet traffic (connection not from a trusted proxy) must not
    // be able to influence its effective IP via a self-reported header.
    if (!this.isTrustedProxy(socketIp, trustedProxies)) {
      return socketIp;
    }

    const forwardedFor = req.headers?.["x-forwarded-for"];
    const chain = this.parseForwardedChain(forwardedFor);
    if (chain.length === 0) {
      return socketIp;
    }

    // Walk from the right (closest hop) to the left, skipping trusted proxies.
    // The first address that is not a trusted proxy is the real client.
    for (let i = chain.length - 1; i >= 0; i--) {
      const hopIp = chain[i];
      if (!this.isTrustedProxy(hopIp, trustedProxies)) {
        return hopIp;
      }
    }

    // All hops in the chain are trusted proxies; fall back to the leftmost
    // address (the original client as reported by the trusted chain).
    return chain[0];
  }

  private getSocketIp(req: RequestWithRateLimitContext): string {
    const remoteAddress =
      req.socket?.remoteAddress ?? req.connection?.remoteAddress ?? req.ip;
    if (typeof remoteAddress === "string" && remoteAddress.length > 0) {
      return this.normalizeIp(remoteAddress);
    }
    return "unknown";
  }

  private getTrustedProxies(): string[] {
    const configured = throttlerConfig.trustedProxies;
    if (Array.isArray(configured)) {
      return configured;
    }
    return [];
  }

  private isTrustedProxy(ip: string, trustedProxies: string[]): boolean {
    if (trustedProxies.length === 0) {
      return false;
    }

    const normalized = this.normalizeIp(ip);
    if (normalized === "unknown") {
      return false;
    }

    for (const entry of trustedProxies) {
      if (this.matchesProxyEntry(normalized, entry)) {
        return true;
      }
    }

    return false;
  }

  private matchesProxyEntry(ip: string, entry: string): boolean {
    try {
      const clientIp = parse(ip);
      if (entry.includes("/")) {
        const [range, prefix] = entry.split("/");
        return parse(range).match(clientIp, parseInt(prefix, 10));
      }
      return clientIp.toString() === parse(entry).toString();
    } catch {
      return false;
    }
  }

  private parseForwardedChain(value: string | string[] | undefined): string[] {
    if (!value) return [];
    const raw = Array.isArray(value) ? value.join(",") : value;
    return raw
      .split(",")
      .map((part) => this.normalizeIp(part.trim()))
      .filter((ip) => ip !== "unknown");
  }

  private normalizeIp(ip: string): string {
    const trimmed = ip.trim();
    if (!trimmed) return "unknown";
    // Strip IPv6 bucket syntax (e.g. "[::1]:443") and zone identifiers.
    const withoutBuckets = trimmed.replace(/^\[([^\]]+)\](.*)$/, "$1");
    const withoutZone = withoutBuckets.split("%")[0];
    try {
      return parse(withoutZone).toString();
    } catch {
      return "unknown";
    }
  }
}
