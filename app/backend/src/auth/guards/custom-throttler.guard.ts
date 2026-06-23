import {
  ExecutionContext,
  Injectable,
  Inject,
  Logger,
} from "@nestjs/common";
import { Reflector } from "@nestjs/core";
import {
  ThrottlerException,
  ThrottlerGuard,
  ThrottlerRequest,
} from "@nestjs/throttler";
import {
  RATE_LIMIT_GROUP_METADATA_KEY,
  RateLimitGroup,
  RateLimitKeyType,
  THROTTLER_BURST_NAME,
  isAbuseSensitiveRoute,
  throttlerConfig,
} from "../../config/rate-limit.config";
import { allowlistConfig } from "../../config/rate-limit-allowlist.config";
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
  correlationId?: string;
  rateLimitContext?: {
    group: RateLimitGroup;
    keyType: RateLimitKeyType;
  };
};

@Injectable()
export class CustomThrottlerGuard extends ThrottlerGuard {
  private readonly logger = new Logger(CustomThrottlerGuard.name);

  @Inject(MetricsService)
  private readonly metricsService: MetricsService;

  protected readonly reflector = new Reflector();

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const req = context
      .switchToHttp()
      .getRequest<RequestWithRateLimitContext>();

    if (this.isAllowlisted(req)) {
      return true;
    }

    return super.canActivate(context);
  }

  protected async handleRequest(
    requestProps: ThrottlerRequest,
  ): Promise<boolean> {
    const { context, throttler } = requestProps;
    const req = context
      .switchToHttp()
      .getRequest<RequestWithRateLimitContext>();

    if (this.isAllowlisted(req)) {
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

        this.metricsService.recordRateLimitedRequest(
          method,
          routePath,
          group,
          req.rateLimitContext.keyType,
        );

        this.logger.warn({
          event: "rate_limit_exceeded",
          method,
          route: routePath,
          group,
          keyType: req.rateLimitContext.keyType,
          ip: this.getIp(req),
          correlationId:
            req.correlationId ??
            (typeof req.headers?.["x-request-id"] === "string"
              ? req.headers["x-request-id"]
              : undefined),
        });
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

  private isAllowlisted(req: RequestWithRateLimitContext): boolean {
    if (!allowlistConfig.enabled) {
      return false;
    }

    const ip = this.getIp(req);
    if (allowlistConfig.ips.has(ip)) {
      return true;
    }

    const apiKey = this.getApiKeyValue(req);
    if (apiKey && allowlistConfig.apiKeys.has(apiKey)) {
      return true;
    }

    return false;
  }

  private resolveGroup(
    context: ExecutionContext,
    req: RequestWithRateLimitContext,
  ): RateLimitGroup {
    const metadataGroup = this.reflector.getAllAndOverride<RateLimitGroup>(
      RATE_LIMIT_GROUP_METADATA_KEY,
      [context.getHandler(), context.getClass()],
    );

    if (metadataGroup === "webhooks") {
      return "webhooks";
    }

    const path =
      `${req.baseUrl ?? ""}${req.route?.path ?? req.path ?? req.originalUrl ?? ""}`.toLowerCase();

    if (path.startsWith("/webhooks") || path.includes("/webhooks/")) {
      return "webhooks";
    }

    if (this.getUserId(req) || this.getApiKeyValue(req)) {
      return "authenticated";
    }

    if (
      metadataGroup === "public_abuse" ||
      isAbuseSensitiveRoute(path)
    ) {
      return "public_abuse";
    }

    if (metadataGroup) {
      return metadataGroup;
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
}
