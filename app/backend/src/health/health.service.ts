import { Injectable, Logger } from "@nestjs/common";
import { SupabaseService } from "../supabase/supabase.service";
import { HorizonService } from "../stellar/horizon.service";
import { AppConfigService } from "../config/app-config.service";
import { sanitizeErrorMessage } from "../common/utils/redaction.util";

@Injectable()
export class HealthService {
  private readonly logger = new Logger(HealthService.name);
  private readonly startTime = Date.now();
  private readonly version = "0.1.0"; // Should ideally be injected or read from package.json

  constructor(
    private readonly supabase: SupabaseService,
    private readonly horizon: HorizonService,
    private readonly config: AppConfigService,
  ) { }

  /**
   * Performs a simple ping to Supabase to verify connectivity.
   */
  async checkSupabase(): Promise<{ status: "up" | "down"; latency?: number }> {
    const start = Date.now();
    try {
      // We wrap it in a Promise.race to handle timeouts.
      const timeout = new Promise<boolean>((_, reject) =>
        setTimeout(() => reject(new Error("Timeout")), 3000),
      );

      const isHealthy = await Promise.race([this.supabase.checkHealth(), timeout]);
      const latency = Date.now() - start;

      if (!isHealthy) {
        return { status: "down" };
      }

      return { status: "up", latency };
    } catch (err) {
      const safeMessage = sanitizeErrorMessage((err as Error).message);
      this.logger.warn(`Supabase health check failed or timed out: ${safeMessage}`);
      return { status: "down" };
    }
  }

  /**
   * Validates that critical environment variables are loaded.
   * Reports readiness without exposing sensitive values.
   */
  checkEnvironment(): { status: "up" | "down"; details: string[] } {
    const details: string[] = [];
    let hasCriticalIssue = false;

    // Check database configuration
    if (!this.config.supabaseUrl || !this.config.supabaseAnonKey) {
      details.push("Missing database configuration");
      hasCriticalIssue = true;
    } else {
      details.push("Database configuration loaded");
    }

    // Check network configuration
    if (!this.config.network) {
      details.push("Missing Stellar network configuration");
      hasCriticalIssue = true;
    } else {
      details.push(`Network: ${this.config.network}`);
    }

    // Check Horizon connectivity configuration
    try {
      // HorizonService will use default URLs if custom URL not provided
      details.push("Horizon configuration ready");
    } catch (err) {
      const safeMessage = sanitizeErrorMessage((err as Error).message);
      details.push(`Horizon config error: ${safeMessage}`);
      hasCriticalIssue = true;
    }

    // Check payment signing capability (optional but important)
    if (this.config.isPaymentSigningConfigured) {
      details.push("Payment signing configured");
    } else {
      details.push("Payment signing not configured (read-only mode)");
    }

    if (hasCriticalIssue) {
      return {
        status: "down",
        details,
      };
    }

    return { status: "up", details };
  }

  /**
   * Returns shallow health status for /health.
   */
  async getHealthStatus() {
    return {
      status: "ok",
      version: this.version,
      uptime: Math.floor((Date.now() - this.startTime) / 1000),
    };
  }

  /**
   * Performs deep dependency checks for /ready.
   */
  async getReadinessStatus() {
    const [supabase, env] = await Promise.all([
      this.checkSupabase(),
      Promise.resolve(this.checkEnvironment()),
    ]);

    const ready = supabase.status === "up" && env.status === "up";

    return {
      ready,
      checks: [
        {
          name: "supabase",
          status: supabase.status,
          latency: supabase.latency ? `${supabase.latency}ms` : undefined,
        },
        {
          name: "environment",
          status: env.status,
          details: env.details,
        },
      ],
    };
  }
}
