import { Injectable, Logger, NestMiddleware } from "@nestjs/common";
import { Request, Response, NextFunction } from "express";
import { AppConfigService } from "../config/app-config.service";
import { MetricsService } from "../metrics/metrics.service";

/**
 * ShadowTrafficMiddleware duplicates read-only requests to production
 * for testing and validation purposes without affecting the staging response.
 *
 * This middleware:
 * - Only operates when SHADOW_TRAFFIC_ENABLED is true
 * - Only shadows GET requests (read-only)
 * - Samples requests based on SHADOW_TRAFFIC_SAMPLE_RATE
 * - Only shadows endpoints listed in SHADOW_TRAFFIC_ENDPOINTS
 * - Never blocks or modifies the original request/response
 * - Logs all shadow attempts for monitoring
 *
 * CRITICAL: This middleware NEVER performs writes and is clearly gated behind
 * environment variables.
 */
@Injectable()
export class ShadowTrafficMiddleware implements NestMiddleware {
  private readonly logger = new Logger(ShadowTrafficMiddleware.name);
  private shadowEndpoints: Set<string>;

  constructor(
    private readonly config: AppConfigService,
    private readonly metricsService: MetricsService,
  ) {
    // Parse shadow endpoints from comma-separated string
    const endpointsStr = this.config.shadowTrafficEndpoints;
    this.shadowEndpoints = new Set(
      endpointsStr
        .split(",")
        .map((e) => e.trim())
        .filter((e) => e.length > 0),
    );
  }

  use(req: Request, res: Response, next: NextFunction) {
    // Skip if shadow traffic is not enabled
    if (!this.config.shadowTrafficEnabled) {
      return next();
    }

    // Only shadow GET requests (read-only)
    if (req.method !== "GET") {
      return next();
    }

    // Check if this endpoint should be shadowed
    const shouldShadow = this.shouldShadowEndpoint(req.path);
    if (!shouldShadow) {
      return next();
    }

    // Apply sampling rate
    if (!this.shouldSample()) {
      this.metricsService.recordShadowTrafficRequest(
        req.method,
        req.path,
        res.statusCode,
        "skipped",
      );
      return next();
    }

    // Fire and forget - shadow the request
    this.shadowRequest(req);

    // Continue with original request without waiting
    next();
  }

  /**
   * Check if the endpoint should be shadowed
   */
  private shouldShadowEndpoint(path: string): boolean {
    for (const endpoint of this.shadowEndpoints) {
      if (path.startsWith(endpoint)) {
        return true;
      }
    }
    return false;
  }

  /**
   * Determine if this request should be sampled based on sample rate
   */
  private shouldSample(): boolean {
    const sampleRate = this.config.shadowTrafficSampleRate;
    return Math.random() < sampleRate;
  }

  /**
   * Shadow the request to production
   * This is fire-and-forget and never affects the original response
   */
  private shadowRequest(req: Request): void {
    const productionUrl = this.config.productionBaseUrl;

    if (!productionUrl) {
      this.logger.warn(
        "Shadow traffic enabled but PRODUCTION_BASE_URL not configured",
      );
      return;
    }

    // Build the shadow URL
    const shadowUrl = `${productionUrl}${req.originalUrl}`;

    // Log shadow attempt
    this.logger.debug(
      `Shadowing request: ${req.method} ${req.path} -> ${shadowUrl}`,
    );

    // Fire and forget - use fetch with timeout
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 5000); // 5 second timeout

    fetch(shadowUrl, {
      method: req.method,
      headers: this.sanitiseHeaders(req.headers),
      signal: controller.signal,
    })
      .then((response) => {
        clearTimeout(timeoutId);
        this.metricsService.recordShadowTrafficRequest(
          req.method,
          req.path,
          response.status,
          "success",
        );
        this.logger.debug(
          `Shadow request successful: ${req.method} ${req.path} -> ${response.status}`,
        );
      })
      .catch((error) => {
        clearTimeout(timeoutId);
        this.metricsService.recordShadowTrafficRequest(
          req.method,
          req.path,
          0,
          "error",
        );

        // Log errors but don't fail the original request
        if (error.name === "AbortError") {
          this.logger.warn(`Shadow request timeout: ${req.method} ${req.path}`);
        } else {
          this.logger.warn(
            `Shadow request failed: ${req.method} ${req.path} - ${error.message}`,
          );
        }
      });
  }

  /**
   * Sanitize headers to remove sensitive information
   * Never forward authentication tokens or API keys to production
   */
  private sanitiseHeaders(headers: Request["headers"]): Record<string, string> {
    const sensitiveHeaders = new Set([
      "authorization",
      "x-api-key",
      "cookie",
      "set-cookie",
      "x-auth-token",
      "access-token",
    ]);

    const sanitized: Record<string, string> = {};

    for (const [key, value] of Object.entries(headers)) {
      if (sensitiveHeaders.has(key.toLowerCase())) {
        continue; // Skip sensitive headers
      }

      if (typeof value === "string") {
        sanitized[key] = value;
      } else if (Array.isArray(value)) {
        sanitized[key] = value.join(",");
      }
    }

    // Add shadow marker header for production to identify shadow traffic
    sanitized["X-Shadow-Traffic"] = "true";

    return sanitized;
  }
}
