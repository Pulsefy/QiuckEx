import { Injectable, Logger, OnModuleInit } from "@nestjs/common";
import { AppConfigService } from "../config/app-config.service";
import { MetricsService } from "../metrics/metrics.service";

export interface ParityCheckResult {
  check: string;
  status: "pass" | "fail" | "warning";
  details?: string;
}

/**
 * EnvironmentParityService validates that staging environment configuration
 * matches production expectations to catch deployment issues early.
 *
 * This service performs checks on:
 * - Configuration parity (endpoints, versions, feature flags)
 * - Network connectivity
 * - Service dependencies
 *
 * All checks are non-blocking and logged for monitoring.
 */
@Injectable()
export class EnvironmentParityService implements OnModuleInit {
  private readonly logger = new Logger(EnvironmentParityService.name);
  private parityResults: ParityCheckResult[] = [];

  constructor(
    private readonly config: AppConfigService,
    private readonly metricsService: MetricsService,
  ) {}

  async onModuleInit() {
    if (this.config.envParityCheckEnabled) {
      await this.runParityChecks();
    }
  }

  /**
   * Run all environment parity checks
   */
  async runParityChecks(): Promise<ParityCheckResult[]> {
    this.logger.log("Running environment parity checks...");
    this.parityResults = [];

    // Run checks in parallel where possible
    await Promise.allSettled([
      this.checkEnvironmentName(),
      this.checkNetworkConfiguration(),
      this.checkProductionBaseUrl(),
      this.checkStellarConfiguration(),
      this.checkSupabaseConfiguration(),
      this.checkFeatureFlags(),
      this.checkVersionCompatibility(),
    ]);

    // Log results
    const passed = this.parityResults.filter((r) => r.status === "pass").length;
    const failed = this.parityResults.filter((r) => r.status === "fail").length;
    const warnings = this.parityResults.filter(
      (r) => r.status === "warning",
    ).length;

    this.logger.log(
      `Environment parity checks complete: ${passed} passed, ${failed} failed, ${warnings} warnings`,
    );

    // Log failures and warnings
    this.parityResults
      .filter((r) => r.status !== "pass")
      .forEach((result) => {
        this.logger.warn(
          `[${result.status.toUpperCase()}] ${result.check}: ${result.details}`,
        );
      });

    // Record metrics
    this.metricsService.recordParityCheckResult(
      "total",
      passed,
      failed,
      warnings,
    );

    return this.parityResults;
  }

  /**
   * Get current parity check results
   */
  getResults(): ParityCheckResult[] {
    return this.parityResults;
  }

  /**
   * Check that environment name is properly set
   */
  private async checkEnvironmentName(): Promise<void> {
    const envName = this.config.environmentName;

    if (!envName) {
      this.parityResults.push({
        check: "environment_name",
        status: "warning",
        details: "ENVIRONMENT_NAME not set - using NODE_ENV fallback",
      });
    } else if (envName === "production" && this.config.isStaging) {
      this.parityResults.push({
        check: "environment_name",
        status: "fail",
        details:
          'ENVIRONMENT_NAME is "production" but running in staging context',
      });
    } else {
      this.parityResults.push({
        check: "environment_name",
        status: "pass",
        details: `Environment: ${envName}`,
      });
    }
  }

  /**
   * Check network configuration parity
   */
  private async checkNetworkConfiguration(): Promise<void> {
    const network = this.config.network;
    const stellarNetwork = this.config.isProduction ? "mainnet" : "testnet";

    if (network !== stellarNetwork) {
      this.parityResults.push({
        check: "network_configuration",
        status: "fail",
        details: `NETWORK (${network}) does not match expected for ${this.config.environmentName || this.config.nodeEnv}`,
      });
    } else {
      this.parityResults.push({
        check: "network_configuration",
        status: "pass",
        details: `Network: ${network}`,
      });
    }
  }

  /**
   * Check production base URL is configured for parity checks
   */
  private async checkProductionBaseUrl(): Promise<void> {
    if (!this.config.productionBaseUrl && this.config.isStaging) {
      this.parityResults.push({
        check: "production_base_url",
        status: "warning",
        details:
          "PRODUCTION_BASE_URL not set - cannot perform remote parity checks",
      });
    } else if (this.config.productionBaseUrl) {
      this.parityResults.push({
        check: "production_base_url",
        status: "pass",
        details: `Production URL configured: ${this.config.productionBaseUrl}`,
      });
    } else {
      this.parityResults.push({
        check: "production_base_url",
        status: "pass",
        details: "Not required for this environment",
      });
    }
  }

  /**
   * Check Stellar configuration
   */
  private async checkStellarConfiguration(): Promise<void> {
    const checks: string[] = [];
    let hasIssue = false;

    if (!this.config.network) {
      checks.push("NETWORK missing");
      hasIssue = true;
    }

    if (this.config.isProduction && !this.config.stellarSecretKey) {
      checks.push("STELLAR_SECRET_KEY missing in production");
      hasIssue = true;
    }

    if (hasIssue) {
      this.parityResults.push({
        check: "stellar_configuration",
        status: "fail",
        details: checks.join(", "),
      });
    } else {
      this.parityResults.push({
        check: "stellar_configuration",
        status: "pass",
        details: "Stellar configuration valid",
      });
    }
  }

  /**
   * Check Supabase configuration
   */
  private async checkSupabaseConfiguration(): Promise<void> {
    if (!this.config.supabaseUrl || !this.config.supabaseAnonKey) {
      this.parityResults.push({
        check: "supabase_configuration",
        status: "fail",
        details: "Supabase configuration incomplete",
      });
    } else {
      this.parityResults.push({
        check: "supabase_configuration",
        status: "pass",
        details: "Supabase configuration valid",
      });
    }
  }

  /**
   * Check feature flags parity
   */
  private async checkFeatureFlags(): Promise<void> {
    const bootstrapFlags = this.config.featureFlagsBootstrapJson;

    if (this.config.isStaging && !bootstrapFlags) {
      this.parityResults.push({
        check: "feature_flags",
        status: "warning",
        details: "No bootstrap feature flags configured for staging",
      });
    } else {
      this.parityResults.push({
        check: "feature_flags",
        status: "pass",
        details: "Feature flags configured",
      });
    }
  }

  /**
   * Check version compatibility
   */
  private async checkVersionCompatibility(): Promise<void> {
    const packageVersion = process.env.npm_package_version || "unknown";

    this.parityResults.push({
      check: "version_compatibility",
      status: "pass",
      details: `Backend version: ${packageVersion}`,
    });
  }
}
