import { Injectable, Logger } from "@nestjs/common";
import { SupabaseService } from "../supabase/supabase.service";
import { HorizonService } from "../stellar/horizon.service";
import { AppConfigService } from "../config/app-config.service";

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
      const client = this.supabase.getClient();

      // Lightweight ping: just select 1 unit.
      // We wrap it in a Promise.race to handle timeouts.
      const timeout = new Promise((_, reject) =>
        setTimeout(() => reject(new Error("Timeout")), 3000),
      );

      const ping = client.from("usernames").select("id").limit(1);

      const result = await Promise.race([ping, timeout]);
      const { error } = result as { error: { message: string } | null };

      const latency = Date.now() - start;

      if (error) {
        this.logger.warn(`Supabase health check failed: ${error.message}`);
        return { status: "down" };
      }

      return { status: "up", latency };
    } catch (err) {
      this.logger.warn(`Supabase health check failed or timed out: ${err.message}`);
      return { status: "down" };
    }
  }

  /**
   * Validates that critical environment variables are loaded.
   */
  checkEnvironment(): { status: "up" | "down"; details: string[] } {
    const criticalVars = [
      "NETWORK",
      "SUPABASE_URL",
      "SUPABASE_ANON_KEY",
    ];

    const missing = criticalVars.filter(v => !process.env[v]);

    if (missing.length > 0) {
      return {
        status: "down",
        details: [`Missing environment variables: ${missing.join(", ")}`],
      };
    }

    return { status: "up", details: ["All critical env variables loaded"] };
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
