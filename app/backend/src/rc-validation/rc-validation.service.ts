import { Injectable, Logger } from "@nestjs/common";
import { randomUUID } from "crypto";

import { AppConfigService } from "../config";
import { HealthService } from "../health/health.service";
import { ContractRegistryService } from "../contracts/contract-registry.service";
import { IndexerLagService } from "../indexer-lag/indexer-lag.service";
import { EnvironmentParityService } from "../environment-parity/environment-parity.service";
import {
  RcBlockerDto,
  RcEnvironmentSectionDto,
  RcLagSectionDto,
  RcOverallStatus,
  RcRegistrySectionDto,
  RcSmokeSectionDto,
  RcValidationReportDto,
} from "./dto/rc-report.dto";

/**
 * Aggregates the signals an operator needs to decide whether a testnet
 * release candidate is safe to ship, into a single reproducible report:
 *
 *  - smoke results      -> deep readiness probes (HealthService)
 *  - registry status    -> active contract deployments (ContractRegistryService)
 *  - lag metrics        -> indexer lag vs. network head (IndexerLagService)
 *  - environment health -> staging/prod parity checks (EnvironmentParityService)
 *
 * Each source is evaluated defensively so that a failure in one section still
 * yields a usable (partial) report instead of failing the whole endpoint.
 */
@Injectable()
export class RcValidationService {
  private readonly logger = new Logger(RcValidationService.name);
  private readonly expectedContracts: string[];

  constructor(
    private readonly config: AppConfigService,
    private readonly health: HealthService,
    private readonly registry: ContractRegistryService,
    private readonly indexerLag: IndexerLagService,
    private readonly environmentParity: EnvironmentParityService,
  ) {
    // Mirror ContractRegistryService's expected-set source so the report
    // agrees with the registry's own notion of a complete deployment.
    this.expectedContracts = (
      process.env.CONTRACT_REGISTRY_EXPECTED_SET ?? "quickex"
    )
      .split(",")
      .map((value) => value.trim().toLowerCase())
      .filter(Boolean);
  }

  /**
   * Generate an on-demand release-candidate validation report. The report is
   * stamped with a unique id and a single generation timestamp so it is
   * reproducible and auditable.
   */
  async generateReport(): Promise<RcValidationReportDto> {
    const generatedAt = new Date().toISOString();
    const blockers: RcBlockerDto[] = [];

    const [smoke, registry, lag, environment] = await Promise.all([
      this.buildSmokeSection(generatedAt, blockers),
      this.buildRegistrySection(generatedAt, blockers),
      this.buildLagSection(generatedAt, blockers),
      this.buildEnvironmentSection(generatedAt, blockers),
    ]);

    const summary = {
      critical: blockers.filter((b) => b.severity === "critical").length,
      warning: blockers.filter((b) => b.severity === "warning").length,
      info: blockers.filter((b) => b.severity === "info").length,
    };

    const overallStatus: RcOverallStatus =
      summary.critical > 0
        ? "blocked"
        : summary.warning > 0 || summary.info > 0
          ? "degraded"
          : "ready";

    return {
      reportId: randomUUID(),
      generatedAt,
      network: this.config.network,
      environment: this.config.environmentName ?? this.config.nodeEnv,
      releaseReady: summary.critical === 0,
      overallStatus,
      sections: { smoke, registry, lag, environment },
      blockers,
      summary,
    };
  }

  // ── Smoke (deep readiness probes) ──────────────────────────────────────────

  private async buildSmokeSection(
    detectedAt: string,
    blockers: RcBlockerDto[],
  ): Promise<RcSmokeSectionDto> {
    try {
      const readiness = await this.health.getReadinessStatus();
      const checks = readiness.checks.map((check) => ({
        name: check.name,
        status: check.status,
        error: check.error,
      }));
      const failed = checks.filter((c) => c.status === "down");
      const passed = checks.length - failed.length;

      for (const check of failed) {
        blockers.push({
          id: `smoke.${check.name}.down`,
          severity: "critical",
          category: "smoke",
          message: `Smoke check '${check.name}' failed${
            check.error ? `: ${check.error}` : ""
          }`,
          remediation: `Restore the '${check.name}' dependency before releasing`,
          detectedAt,
        });
      }

      return {
        status: readiness.ready ? "pass" : "fail",
        ready: readiness.ready,
        checks,
        passed,
        failed: failed.length,
      };
    } catch (error) {
      this.logger.error("Smoke section evaluation failed", error as Error);
      blockers.push({
        id: "smoke.unavailable",
        severity: "critical",
        category: "smoke",
        message: "Unable to evaluate smoke/readiness checks",
        remediation: "Investigate the health subsystem",
        detectedAt,
      });
      return {
        status: "unknown",
        ready: false,
        checks: [],
        passed: 0,
        failed: 0,
      };
    }
  }

  // ── Registry (active contract deployments) ─────────────────────────────────

  private async buildRegistrySection(
    detectedAt: string,
    blockers: RcBlockerDto[],
  ): Promise<RcRegistrySectionDto> {
    try {
      const registry = await this.registry.getRegistry();
      const activeNames = Object.keys(registry.data).map((name) =>
        name.toLowerCase(),
      );
      const missing = this.expectedContracts.filter(
        (name) => !activeNames.includes(name),
      );

      let status: RcRegistrySectionDto["status"] = "pass";
      if (missing.length > 0) {
        status = "fail";
        blockers.push({
          id: "registry.missing-contracts",
          severity: "critical",
          category: "registry",
          message: `Registry is missing expected contract(s): ${missing.join(
            ", ",
          )}`,
          remediation:
            "Publish the missing contract deployment(s) to the registry",
          detectedAt,
        });
      }

      if (!registry.authoritative) {
        status = status === "fail" ? "fail" : "warning";
        blockers.push({
          id: "registry.not-authoritative",
          severity: "warning",
          category: "registry",
          message: "Contract registry is not marked authoritative",
          remediation: "Finalize registry dual-read before release",
          detectedAt,
        });
      }

      return {
        status,
        network: registry.network,
        authoritative: registry.authoritative,
        version: registry.version,
        activeContracts: activeNames.length,
        expectedContracts: this.expectedContracts,
        missingContracts: missing,
      };
    } catch (error) {
      this.logger.error("Registry section evaluation failed", error as Error);
      blockers.push({
        id: "registry.unavailable",
        severity: "critical",
        category: "registry",
        message: "Unable to read contract registry status",
        remediation: "Investigate the contract registry subsystem",
        detectedAt,
      });
      return {
        status: "unknown",
        network: this.config.network,
        authoritative: false,
        version: 0,
        activeContracts: 0,
        expectedContracts: this.expectedContracts,
        missingContracts: this.expectedContracts,
      };
    }
  }

  // ── Lag metrics (indexer vs. network head) ─────────────────────────────────

  private buildLagSection(
    detectedAt: string,
    blockers: RcBlockerDto[],
  ): RcLagSectionDto {
    try {
      const status = this.indexerLag.getStatus();
      const isBlocking = this.indexerLag.isBlocked();

      let sectionStatus: RcLagSectionDto["status"] = "pass";
      if (isBlocking) {
        sectionStatus = "fail";
        blockers.push({
          id: "lag.blocking",
          severity: "critical",
          category: "lag",
          message: `Indexer lag (${status.lagLedgers} ledgers) exceeds threshold (${status.thresholdLedgers}) and is blocking traffic`,
          remediation: "Allow the indexer to catch up before releasing",
          detectedAt,
        });
      } else if (status.isLagging) {
        // Lagging but not blocking (guard disabled or overridden).
        sectionStatus = "warning";
        blockers.push({
          id: "lag.lagging",
          severity: "warning",
          category: "lag",
          message: `Indexer is lagging by ${status.lagLedgers} ledgers (threshold ${status.thresholdLedgers}) but the guard is not enforcing`,
          remediation: "Verify the indexer-lag guard configuration",
          detectedAt,
        });
      } else if (
        status.currentNetworkLedger === null ||
        status.lastIndexedLedger === null
      ) {
        // Lag cannot be computed yet — surface as advisory, not a hard block.
        sectionStatus = "warning";
        blockers.push({
          id: "lag.unknown",
          severity: "info",
          category: "lag",
          message: "Indexer lag could not be computed (no ledger data yet)",
          remediation: "Confirm ingestion is running and reporting checkpoints",
          detectedAt,
        });
      }

      return {
        status: sectionStatus,
        currentNetworkLedger: status.currentNetworkLedger,
        lastIndexedLedger: status.lastIndexedLedger,
        lagLedgers: status.lagLedgers,
        isLagging: status.isLagging,
        isBlocking,
        thresholdLedgers: status.thresholdLedgers,
      };
    } catch (error) {
      this.logger.error("Lag section evaluation failed", error as Error);
      blockers.push({
        id: "lag.unavailable",
        severity: "warning",
        category: "lag",
        message: "Unable to read indexer lag metrics",
        remediation: "Investigate the indexer-lag subsystem",
        detectedAt,
      });
      return {
        status: "unknown",
        currentNetworkLedger: null,
        lastIndexedLedger: null,
        lagLedgers: null,
        isLagging: false,
        isBlocking: false,
        thresholdLedgers: 0,
      };
    }
  }

  // ── Environment health (staging/prod parity) ───────────────────────────────

  private buildEnvironmentSection(
    detectedAt: string,
    blockers: RcBlockerDto[],
  ): RcEnvironmentSectionDto {
    try {
      const results = this.environmentParity.getResults();
      const failed = results.filter((r) => r.status === "fail");
      const warnings = results.filter((r) => r.status === "warning");
      const passed = results.filter((r) => r.status === "pass");

      for (const result of failed) {
        blockers.push({
          id: `environment.${result.check}.fail`,
          severity: "warning",
          category: "environment",
          message: `Environment parity check '${result.check}' failed${
            result.details ? `: ${result.details}` : ""
          }`,
          remediation: "Reconcile staging configuration with production",
          detectedAt,
        });
      }

      for (const result of warnings) {
        blockers.push({
          id: `environment.${result.check}.warning`,
          severity: "info",
          category: "environment",
          message: `Environment parity check '${result.check}' raised a warning${
            result.details ? `: ${result.details}` : ""
          }`,
          detectedAt,
        });
      }

      const status: RcEnvironmentSectionDto["status"] =
        failed.length > 0 ? "fail" : warnings.length > 0 ? "warning" : "pass";

      return {
        status,
        checks: results,
        passed: passed.length,
        failed: failed.length,
        warnings: warnings.length,
      };
    } catch (error) {
      this.logger.error(
        "Environment section evaluation failed",
        error as Error,
      );
      blockers.push({
        id: "environment.unavailable",
        severity: "warning",
        category: "environment",
        message: "Unable to read environment parity results",
        remediation: "Investigate the environment-parity subsystem",
        detectedAt,
      });
      return {
        status: "unknown",
        checks: [],
        passed: 0,
        failed: 0,
        warnings: 0,
      };
    }
  }
}
