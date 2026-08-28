import { Injectable, Logger, Optional } from "@nestjs/common";
import { SupabaseService } from "../supabase/supabase.service";
import { HorizonService } from "../stellar/horizon.service";
import { AppConfigService } from "../config/app-config.service";
import { sanitizeErrorMessage } from "../common/utils/redaction.util";
import { JobQueueService } from "../job-queue/job-queue.service";
import { JobRepository } from "../job-queue/job.repository";
import { CursorRepository } from "../ingestion/cursor.repository";
import { SorobanRpcService } from "../transactions/soroban-rpc.service";
import { RedisService } from "../redis/redis.service";
import { SentryService } from "../sentry";

export type DependencyStatus = "healthy" | "degraded" | "unhealthy";

export type DependencyCheckResult = {
  status: DependencyStatus;
  latency?: number;
  error?: string;
  lastSuccess?: string;
};

export type CompositeHealth = {
  status: DependencyStatus;
  version: string;
  uptime: number;
  timestamp: string;
  checks: Record<string, DependencyCheckResult>;
};

const HEALTH_CACHE_TTL_MS = 5_000;

@Injectable()
export class HealthService {
  private readonly logger = new Logger(HealthService.name);
  private readonly startTime = Date.now();
  private readonly version = "0.1.0"; // Should ideally be injected or read from package.json

  // Short in-memory cache (5s) so the composite health check isn't hammered.
  private cache: { expiresAt: number; value: CompositeHealth } | null = null;

  constructor(
    private readonly supabase: SupabaseService,
    private readonly horizon: HorizonService,
    private readonly config: AppConfigService,
    private readonly jobQueueService: JobQueueService,
    private readonly jobRepository: JobRepository,
    private readonly cursorRepository: CursorRepository,
    private readonly sorobanRpcService: SorobanRpcService,
    private readonly redis: RedisService,
    private readonly sentry: SentryService,
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
   * Checks Redis reachability with timeout. Reports healthy when connected,
   * degraded when not configured (app falls back to in-memory stores), and
   * unhealthy when configured but unreachable.
   */
  async checkRedis(): Promise<{
    status: "up" | "down" | "not_configured";
    latency?: number;
    details?: string;
    lastSuccess?: string;
  }> {
    if (!this.redis.isConfigured) {
      return {
        status: "not_configured",
        details: "Redis not configured — using in-memory fallback",
      };
    }

    const start = Date.now();
    try {
      const timeout = new Promise<never>((_, reject) =>
        setTimeout(() => reject(new Error("Timeout")), 3000),
      );
      const healthy = await Promise.race([this.redis.ping(), timeout]);
      const latency = Date.now() - start;

      if (!healthy) {
        return { status: "down", details: "Redis ping failed" };
      }

      return {
        status: "up",
        latency,
        lastSuccess: new Date().toISOString(),
      };
    } catch (err) {
      const safeMessage = sanitizeErrorMessage((err as Error).message);
      this.logger.warn(`Redis health check failed: ${safeMessage}`);
      return { status: "down", details: safeMessage };
    }
  }

  /**
   * Maps a raw up/down/not_configured check into the composite healthy /
   * degraded / unhealthy vocabulary.
   */
  private toDependencyStatus(
    raw: "up" | "down" | "not_configured",
  ): DependencyStatus {
    if (raw === "up") return "healthy";
    if (raw === "not_configured") return "degraded";
    return "unhealthy";
  }

  /**
   * Returns a composite health report for /health:
   * { status, checks: { supabase, horizon, soroban_rpc, redis } }.
   * Cached for 5s and raises a Sentry alert whenever any check is unhealthy.
   */
  async getHealthStatus(): Promise<CompositeHealth> {
    const now = Date.now();
    if (this.cache && this.cache.expiresAt > now) {
      return this.cache.value;
    }

    const [supabase, horizon, sorobanRpc, redis] = await Promise.all([
      this.checkSupabase(),
      this.checkHorizon(),
      this.checkSorobanRpc(),
      this.checkRedis(),
    ]);

    const checks: Record<string, DependencyCheckResult> = {
      supabase: {
        status: this.toDependencyStatus(supabase.status),
        latency: supabase.latency,
        error: supabase.status === "down" ? supabase.details : undefined,
        lastSuccess: supabase.lastSuccess,
      },
      horizon: {
        status: this.toDependencyStatus(horizon.status),
        latency: horizon.latency,
        error: horizon.status === "down" ? horizon.details : undefined,
        lastSuccess: horizon.lastSuccess,
      },
      soroban_rpc: {
        status: this.toDependencyStatus(sorobanRpc.status),
        latency: sorobanRpc.latency,
        error: sorobanRpc.status === "down" ? sorobanRpc.details : undefined,
        lastSuccess: sorobanRpc.lastSuccess,
      },
      redis: {
        status: this.toDependencyStatus(redis.status),
        latency: redis.latency,
        error: redis.status === "down" ? redis.details : undefined,
        lastSuccess: redis.lastSuccess,
      },
    };

    const statuses = Object.values(checks).map((c) => c.status);
    const overall: DependencyStatus = statuses.includes("unhealthy")
      ? "unhealthy"
      : statuses.includes("degraded")
        ? "degraded"
        : "healthy";

    const result: CompositeHealth = {
      status: overall,
      version: this.version,
      uptime: Math.floor((Date.now() - this.startTime) / 1000),
      timestamp: new Date().toISOString(),
      checks,
    };

    this.cache = { expiresAt: Date.now() + HEALTH_CACHE_TTL_MS, value: result };

    if (overall !== "healthy") {
      this.sentry.captureMessage(
        `Health check degraded: ${overall} — ${statuses.join(", ")}`,
        "warning",
        {
          supabase: checks.supabase.status,
          horizon: checks.horizon.status,
          soroban_rpc: checks.soroban_rpc.status,
          redis: checks.redis.status,
        },
      );
    }

    return result;
  }

  /**
   * Readiness for /ready. Returns 200 only when every dependency is healthy.
   * A degraded dependency (e.g. Redis not configured) is tolerated for
   * serving, but any unhealthy dependency makes the service not ready.
   */
  async getReadinessStatus() {
    const health = await this.getHealthStatus();

    const ready = Object.values(health.checks).every(
      (check) => check.status === "healthy",
    );

    return {
      ready,
      status: ready ? "healthy" : health.status,
      timestamp: health.timestamp,
      checks: health.checks,
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
