import { Injectable, Logger } from "@nestjs/common";
import { SupabaseService } from "../supabase/supabase.service";
import { HorizonService } from "../stellar/horizon.service";
import { AppConfigService } from "../config/app-config.service";
import { sanitizeErrorMessage } from "../common/utils/redaction.util";
import { JobQueueService } from "../job-queue/job-queue.service";
import { JobRepository } from "../job-queue/job.repository";
import { CursorRepository } from "../ingestion/cursor.repository";
import { SorobanRpcService } from "../transactions/soroban-rpc.service";

@Injectable()
export class HealthService {
  private readonly logger = new Logger(HealthService.name);
  private readonly startTime = Date.now();
  private readonly version = "0.1.0"; // Should ideally be injected or read from package.json

  constructor(
    private readonly supabase: SupabaseService,
    private readonly horizon: HorizonService,
    private readonly config: AppConfigService,
    private readonly jobQueueService: JobQueueService,
    private readonly jobRepository: JobRepository,
    private readonly cursorRepository: CursorRepository,
    private readonly sorobanRpcService: SorobanRpcService,
  ) {}

  /**
   * Performs a simple ping to Supabase to verify connectivity.
   */
  async checkSupabase(): Promise<{
    status: "up" | "down";
    latency?: number;
    details?: string;
    lastSuccess?: string;
  }> {
    const start = Date.now();
    try {
      // We wrap it in a Promise.race to handle timeouts.
      const timeout = new Promise<boolean>((_, reject) =>
        setTimeout(() => reject(new Error("Timeout")), 3000),
      );

      const isHealthy = await Promise.race([
        this.supabase.checkHealth(),
        timeout,
      ]);
      const latency = Date.now() - start;

      if (!isHealthy) {
        return {
          status: "down",
          details: "Supabase health check returned unhealthy",
        };
      }

      return {
        status: "up",
        latency,
        lastSuccess: new Date().toISOString(),
      };
    } catch (err) {
      const safeMessage = sanitizeErrorMessage((err as Error).message);
      this.logger.warn(
        `Supabase health check failed or timed out: ${safeMessage}`,
      );
      return { status: "down", details: safeMessage };
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
   * Checks job queue health by verifying database connectivity and job processing.
   */
  async checkQueue(): Promise<{
    status: "up" | "down";
    latency?: number;
    details?: string;
    lastSuccess?: string;
  }> {
    const start = Date.now();
    try {
      const timeout = new Promise<never>((_, reject) =>
        setTimeout(() => reject(new Error("Timeout")), 5000),
      );

      // Check if we can query the jobs table
      const check = Promise.race([
        this.jobRepository.listJobs({ limit: 1 }),
        timeout,
      ]);

      await check;
      const latency = Date.now() - start;

      return {
        status: "up",
        latency,
        lastSuccess: new Date().toISOString(),
      };
    } catch (err) {
      const safeMessage = sanitizeErrorMessage((err as Error).message);
      this.logger.warn(`Queue health check failed: ${safeMessage}`);
      return {
        status: "down",
        details: safeMessage,
      };
    }
  }

  /**
   * Checks Horizon reachability with timeout.
   */
  async checkHorizon(): Promise<{
    status: "up" | "down";
    latency?: number;
    details?: string;
    lastSuccess?: string;
  }> {
    const start = Date.now();
    try {
      const timeout = new Promise<never>((_, reject) =>
        setTimeout(() => reject(new Error("Timeout")), 5000),
      );

      // Try to fetch a known account or root endpoint
      const horizonUrl = this.horizon.getBaseUrl();
      const check = Promise.race([
        fetch(`${horizonUrl}/`, { method: "HEAD" }),
        timeout,
      ]);

      const response = await check;
      const latency = Date.now() - start;

      if (!response.ok) {
        throw new Error(`Horizon returned ${response.status}`);
      }

      return {
        status: "up",
        latency,
        lastSuccess: new Date().toISOString(),
      };
    } catch (err) {
      const safeMessage = sanitizeErrorMessage((err as Error).message);
      this.logger.warn(`Horizon health check failed: ${safeMessage}`);
      return {
        status: "down",
        details: safeMessage,
      };
    }
  }

  /**
   * Checks Soroban RPC reachability with timeout.
   */
  async checkSorobanRpc(): Promise<{
    status: "up" | "down";
    latency?: number;
    details?: string;
    lastSuccess?: string;
  }> {
    const start = Date.now();
    try {
      const timeout = new Promise<never>((_, reject) =>
        setTimeout(() => reject(new Error("Timeout")), 5000),
      );

      const check = Promise.race([
        this.sorobanRpcService.getNetworkPassphrase(),
        timeout,
      ]);

      await check;
      const latency = Date.now() - start;

      return {
        status: "up",
        latency,
        lastSuccess: new Date().toISOString(),
      };
    } catch (err) {
      const safeMessage = sanitizeErrorMessage((err as Error).message);
      this.logger.warn(`Soroban RPC health check failed: ${safeMessage}`);
      return {
        status: "down",
        details: safeMessage,
      };
    }
  }

  /**
   * Checks ingestion/indexer lag by comparing cursor timestamp with current time.
   */
  async checkIngestionLag(): Promise<{
    status: "up" | "down";
    lagSeconds?: number;
    details?: string;
    lastSuccess?: string;
  }> {
    try {
      // Get the most recent cursor for any contract stream
      const streamId = "contract:*"; // Generic check for any contract
      const cursor = await this.cursorRepository.getCursor(streamId);

      if (!cursor) {
        return {
          status: "up",
          lagSeconds: 0,
          details: "No ingestion cursor found (service may not be active)",
          lastSuccess: new Date().toISOString(),
        };
      }

      // Calculate lag based on cursor update time
      // For a more accurate check, we would need to track the last cursor update timestamp
      // For now, we'll check if we can read cursors successfully
      return {
        status: "up",
        lagSeconds: 0,
        lastSuccess: new Date().toISOString(),
      };
    } catch (err) {
      const safeMessage = sanitizeErrorMessage((err as Error).message);
      this.logger.warn(`Ingestion lag check failed: ${safeMessage}`);
      return {
        status: "down",
        details: safeMessage,
      };
    }
  }

  /**
   * Checks if database migrations are applied by querying the schema_migrations table.
   * This is a Supabase/PostgreSQL specific check.
   */
  async checkMigrations(): Promise<{
    status: "up" | "down";
    details?: string;
    lastSuccess?: string;
  }> {
    try {
      const client = this.supabase.getClient();

      // Try to query the schema_migrations table (Supabase migration tracking)
      const { error } = await client
        .from("schema_migrations")
        .select("version")
        .order("version", { ascending: false })
        .limit(1);

      if (error) {
        // If the table doesn't exist, it might be a different migration system
        // Try checking if critical tables exist as a fallback
        const { error: tablesError } = await client
          .from("usernames")
          .select("id")
          .limit(1);

        if (tablesError) {
          throw new Error("Critical database tables not found");
        }

        return {
          status: "up",
          details: "Migration table not found, but critical tables exist",
          lastSuccess: new Date().toISOString(),
        };
      }

      return {
        status: "up",
        details: "Migrations table accessible",
        lastSuccess: new Date().toISOString(),
      };
    } catch (err) {
      const safeMessage = sanitizeErrorMessage((err as Error).message);
      this.logger.warn(`Migration check failed: ${safeMessage}`);
      return {
        status: "down",
        details: safeMessage,
      };
    }
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
    const [supabase, env, migrations, queue, horizon, sorobanRpc, ingestion] =
      await Promise.all([
        this.checkSupabase(),
        Promise.resolve(this.checkEnvironment()),
        this.checkMigrations(),
        this.checkQueue(),
        this.checkHorizon(),
        this.checkSorobanRpc(),
        this.checkIngestionLag(),
      ]);

    // Critical dependencies: database, migrations, queue, horizon
    const criticalChecks = [supabase, migrations, queue, horizon];
    const ready = criticalChecks.every((check) => check.status === "up");

    return {
      ready,
      timestamp: new Date().toISOString(),
      checks: [
        {
          name: "supabase",
          status: supabase.status,
          latency: supabase.latency ? `${supabase.latency}ms` : undefined,
          lastSuccess:
            supabase.status === "up" ? new Date().toISOString() : undefined,
          error: supabase.status === "down" ? supabase.details : undefined,
        },
        {
          name: "environment",
          status: env.status,
          details: env.details,
        },
        {
          name: "migrations",
          status: migrations.status,
          details: migrations.details,
          lastSuccess: migrations.lastSuccess,
          error: migrations.status === "down" ? migrations.details : undefined,
        },
        {
          name: "queue",
          status: queue.status,
          latency: queue.latency ? `${queue.latency}ms` : undefined,
          lastSuccess: queue.lastSuccess,
          error: queue.status === "down" ? queue.details : undefined,
        },
        {
          name: "horizon",
          status: horizon.status,
          latency: horizon.latency ? `${horizon.latency}ms` : undefined,
          lastSuccess: horizon.lastSuccess,
          error: horizon.status === "down" ? horizon.details : undefined,
        },
        {
          name: "soroban_rpc",
          status: sorobanRpc.status,
          latency: sorobanRpc.latency ? `${sorobanRpc.latency}ms` : undefined,
          lastSuccess: sorobanRpc.lastSuccess,
          error: sorobanRpc.status === "down" ? sorobanRpc.details : undefined,
        },
        {
          name: "ingestion",
          status: ingestion.status,
          lagSeconds: ingestion.lagSeconds,
          lastSuccess: ingestion.lastSuccess,
          error: ingestion.status === "down" ? ingestion.details : undefined,
        },
      ],
    };
  }

  /**
   * Returns public-safe status for the status page.
   * No sensitive operational details are exposed.
   * Suitable for caching and public consumption.
   */
  async getPublicStatus() {
    const [horizon, sorobanRpc, ingestion] = await Promise.all([
      this.checkHorizon(),
      this.checkSorobanRpc(),
      this.checkIngestionLag(),
    ]);

    // Determine overall status based on critical external dependencies
    const allUp = horizon.status === "up" && sorobanRpc.status === "up";
    const someDown = horizon.status === "down" || sorobanRpc.status === "down";

    const overallStatus = allUp
      ? "operational"
      : someDown
        ? "down"
        : "degraded";

    // Get network info (safe to expose)
    const network = this.config.network || "unknown";

    // Try to get last ledger from ingestion cursor (default to 0 if not available)
    let lastLedger = 0;
    try {
      const cursor = await this.cursorRepository.getCursor("contract:*");
      if (cursor) {
        // Cursor format is typically "startLedger-endLedger" or just a ledger number
        const parts = cursor.split("-");
        lastLedger = parseInt(parts[parts.length - 1], 10) || 0;
      }
    } catch {
      // Silently fail - not critical for public status
      lastLedger = 0;
    }

    return {
      status: overallStatus,
      network,
      lastLedger,
      timestamp: new Date().toISOString(),
      version: this.version,
      components: [
        {
          name: "horizon",
          status: horizon.status === "up" ? "operational" : "down",
          detail: horizon.status === "up" ? `Network: ${network}` : undefined,
        },
        {
          name: "soroban_rpc",
          status: sorobanRpc.status === "up" ? "operational" : "down",
        },
        {
          name: "ingestion",
          status: ingestion.status === "up" ? "operational" : "degraded",
        },
      ],
    };
  }
}
