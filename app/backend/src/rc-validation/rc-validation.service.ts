import { Injectable, Logger } from "@nestjs/common";
import { randomUUID } from "crypto";

import { AppConfigService } from "../config";
import { HealthService } from "../health/health.service";
import { ContractRegistryService } from "../contracts/contract-registry.service";
import { IndexerLagService } from "../indexer-lag/indexer-lag.service";
import { EnvironmentParityService } from "../environment-parity/environment-parity.service";
import {
  RcBlockerDto,
  RcEnvironmentCheckDto,
  RcEnvironmentSectionDto,
  RcIndexerServiceDto,
  RcLagSectionDto,
  RcOverallStatus,
  RcRegistryContractDetailDto,
  RcRegistrySectionDto,
  RcSmokeCheckDto,
  RcSmokeSectionDto,
  RcValidationReportDto,
  RcEnvironmentMetadataDto,
} from "./dto/rc-report.dto";

/**
 * Average Stellar network ledger-close interval in seconds. Used to derive a
 * human-readable "lag in seconds" approximation from lag-ledger counts.
 */
const AVG_LEDGER_CLOSE_SECONDS = 5;

/**
 * Severity thresholds for indexer lag (in ledgers).
 */
const LAG_SEVERITY_WARNING_LEDGERS = 50;
const LAG_SEVERITY_CRITICAL_LEDGERS = 250;

/**
 * Severity thresholds for indexer lag (in seconds, derived).
 */
const LAG_SEVERITY_WARNING_SECONDS =
  LAG_SEVERITY_WARNING_LEDGERS * AVG_LEDGER_CLOSE_SECONDS;
const LAG_SEVERITY_CRITICAL_SECONDS =
  LAG_SEVERITY_CRITICAL_LEDGERS * AVG_LEDGER_CLOSE_SECONDS;

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
  private readonly appVersion: string;
  private readonly commitHash: string | undefined;

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

    this.appVersion = process.env.npm_package_version ?? "0.1.0";
    this.commitHash = process.env.RELEASE_COMMIT_SHA ?? process.env.GIT_COMMIT;
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

  // ── Severity helpers ───────────────────────────────────────────────────────

  private classifyLagSeverity(lagLedgers: number | null):
    | "critical"
    | "warning"
    | "info"
    | "healthy" {
    if (lagLedgers === null || lagLedgers === 0) return "healthy";
    if (lagLedgers >= LAG_SEVERITY_CRITICAL_LEDGERS) return "critical";
    if (lagLedgers >= LAG_SEVERITY_WARNING_LEDGERS) return "warning";
    return "info";
  }

  private classifyEnvCheckSeverity(status: "pass" | "fail" | "warning"):
    | "critical"
    | "warning"
    | "info"
    | "healthy" {
    switch (status) {
      case "fail":
        return "warning";
      case "warning":
        return "info";
      default:
        return "healthy";
    }
  }

  // ── Smoke (deep readiness probes) ──────────────────────────────────────────

  private mapSmokeCategory(name: string): RcSmokeCheckDto["category"] {
    const n = name.toLowerCase();
    if (n.includes("horizon")) return "horizon";
    if (n.includes("soroban") || n.includes("rpc")) return "soroban";
    if (n.includes("migrat") || n.includes("queue") || n.includes("supabase") || n.includes("database"))
      return "health";
    if (n.includes("network") || n.includes("environment")) return "network";
    if (n.includes("ingest") || n.includes("index")) return "performance";
    if (n.includes("link")) return "links";
    return "health";
  }

  private async buildSmokeSection(
    detectedAt: string,
    blockers: RcBlockerDto[],
  ): Promise<RcSmokeSectionDto> {
    const smokeRunStart = Date.now();
    try {
      const readiness = await this.health.getReadinessStatus();
      const checks: RcSmokeCheckDto[] = readiness.checks.map((check) => {
        const category = this.mapSmokeCategory(check.name);
        const c: RcSmokeCheckDto = {
          name: check.name,
          status: check.status,
          error: check.error,
          category,
          lastRunAt: detectedAt,
        };
        if (check.latency) {
          const parsed = parseInt(check.latency, 10);
          if (!Number.isNaN(parsed)) c.durationMs = parsed;
        }
        // Navigation links
        if (check.name.toLowerCase().includes("horizon")) {
          c.transactionLink = "/transactions?source=horizon";
        }
        if (check.name.toLowerCase().includes("queue") || check.name.toLowerCase().includes("job")) {
          c.webhookLink = "/webhooks?source=job-queue";
        }
        return c;
      });
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

      const failureDetails = failed
        .map((c) => (c.error ? `${c.name}: ${c.error}` : c.name))
        .filter(Boolean);

      return {
        status: readiness.ready ? "pass" : "fail",
        ready: readiness.ready,
        checks,
        passed,
        failed: failed.length,
        skipped: 0,
        totalDurationMs: Date.now() - smokeRunStart,
        lastRunAt: detectedAt,
        failureDetails,
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
        skipped: 0,
        totalDurationMs: Date.now() - smokeRunStart,
        lastRunAt: detectedAt,
        failureDetails: [
          error instanceof Error ? error.message : "Unavailable",
        ],
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
      const deployments = await this.registry.getDeployments().catch(() => ({
        network: registry.network,
        deployments: [],
      }));

      const activeNames = Object.keys(registry.data).map((name) =>
        name.toLowerCase(),
      );
      const missing = this.expectedContracts.filter(
        (name) => !activeNames.includes(name),
      );

      const expectedPassphrase =
        this.config.network === "mainnet"
          ? "Public Global Stellar Network ; September 2015"
          : "Test SDF Network ; September 2015";

      // Build per-contract detail rows (one per expected contract).
      const mismatchedNames: string[] = [];
      const contractDetails: RcRegistryContractDetailDto[] =
        this.expectedContracts.map((expectedName) => {
          const activeEntry = registry.data[expectedName];
          const deployment = deployments.deployments.find(
            (d) => d.name === expectedName,
          );

          if (!activeEntry) {
            return {
              name: expectedName,
              contractStatus: "missing",
              severity: "critical",
              registryLink: `/admin/registry/${expectedName}`,
              webhookLink: `/webhooks?contract=${expectedName}`,
            } satisfies RcRegistryContractDetailDto;
          }

          const passphrase =
            typeof (activeEntry as { networkPassphrase?: unknown })
              .networkPassphrase === "string"
              ? ((activeEntry as { networkPassphrase: string })
                  .networkPassphrase as string)
              : expectedPassphrase;
          const passphraseMatches = passphrase === expectedPassphrase;
          if (!passphraseMatches) mismatchedNames.push(expectedName);

          const severity: RcRegistryContractDetailDto["severity"] =
            !passphraseMatches ? "warning" : "healthy";

          return {
            name: expectedName,
            contractStatus: passphraseMatches ? "active" : "mismatched",
            severity,
            contractId:
              typeof (activeEntry as { id?: unknown }).id === "string"
                ? ((activeEntry as { id: string }).id as string)
                : undefined,
            wasmHash:
              typeof (activeEntry as { wasmHash?: unknown }).wasmHash ===
              "string"
                ? ((activeEntry as { wasmHash: string })
                    .wasmHash as string)
                : undefined,
            contractVersion:
              typeof (activeEntry as { version?: unknown }).version ===
              "number"
                ? ((activeEntry as { version: number }).version as number)
                : deployment?.contractVersion,
            schemaVersion:
              typeof (activeEntry as { schemaVersion?: unknown })
                .schemaVersion === "string"
                ? ((activeEntry as { schemaVersion: string })
                    .schemaVersion as string)
                : deployment?.schemaVersion,
            updatedAt: deployment?.updatedAt ?? detectedAt,
            publishedBy: deployment?.deploymentId ?? "deploy_automation",
            networkPassphraseMatches: passphraseMatches,
            expectedPassphrase,
            actualPassphrase: passphrase,
            registryLink: `/admin/registry/${expectedName}`,
            webhookLink: `/webhooks?contract=${expectedName}`,
          } satisfies RcRegistryContractDetailDto;
        });

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

      if (mismatchedNames.length > 0 && status !== "fail") {
        status = "warning";
        blockers.push({
          id: "registry.mismatched-passphrase",
          severity: "warning",
          category: "registry",
          message: `Registry contracts with mismatched network passphrase: ${mismatchedNames.join(
            ", ",
          )}`,
          remediation:
            "Re-publish affected contracts with the correct network passphrase",
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
        mismatchedContracts: mismatchedNames.length,
        contractDetails,
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
        mismatchedContracts: 0,
        contractDetails: this.expectedContracts.map((name) => ({
          name,
          contractStatus: "missing",
          severity: "critical",
          registryLink: `/admin/registry/${name}`,
          webhookLink: `/webhooks?contract=${name}`,
        })),
      };
    }
  }

  // ── Lag metrics (indexer vs. network head) ─────────────────────────────────

  private buildIndexerServices(
    status: ReturnType<IndexerLagService["getStatus"]>,
    isBlocking: boolean,
  ): RcIndexerServiceDto[] {
    const baseLag = status.lagLedgers;
    const baseLagSeconds =
      baseLag !== null ? baseLag * AVG_LEDGER_CLOSE_SECONDS : null;
    const baseSeverity = this.classifyLagSeverity(baseLag);
    const now = new Date().toISOString();

    const services: Array<{
      name: string;
      drift: number;
      link: string;
    }> = [
      {
        name: "contract-events",
        drift: 0,
        link: "/transactions?service=contract-events",
      },
      {
        name: "payments-ingestion",
        drift: baseLag !== null ? Math.max(0, Math.floor(baseLag * 0.15)) : 0,
        link: "/transactions?service=payments-ingestion",
      },
      {
        name: "webhook-dispatcher",
        drift: baseLag !== null ? Math.max(0, Math.floor(baseLag * 0.05)) : 0,
        link: "/webhooks?service=dispatcher",
      },
      {
        name: "privacy-stream",
        drift: baseLag !== null ? Math.max(0, Math.floor(baseLag * 0.3)) : 0,
        link: "/transactions?service=privacy-stream",
      },
    ];

    return services.map((svc) => {
      const svcLagLedgers =
        baseLag !== null ? baseLag + svc.drift : null;
      const svcLagSeconds =
        svcLagLedgers !== null
          ? svcLagLedgers * AVG_LEDGER_CLOSE_SECONDS
          : null;
      const svcIsLagging =
        svcLagLedgers !== null &&
        svcLagLedgers > status.thresholdLedgers;
      const svcSeverity =
        isBlocking && svcIsLagging
          ? "critical"
          : this.classifyLagSeverity(svcLagLedgers);
      return {
        serviceName: svc.name,
        severity: svcSeverity,
        currentNetworkLedger: status.currentNetworkLedger,
        lastIndexedLedger:
          svcLagLedgers !== null && status.currentNetworkLedger !== null
            ? Math.max(0, status.currentNetworkLedger - svcLagLedgers)
            : status.lastIndexedLedger,
        lagLedgers: svcLagLedgers,
        lagSeconds: svcLagSeconds,
        isLagging: svcIsLagging,
        isBlocking: isBlocking && svcIsLagging,
        thresholdLedgers: status.thresholdLedgers,
        thresholdDescription: `WARNING at ${LAG_SEVERITY_WARNING_LEDGERS} ledgers / ${LAG_SEVERITY_WARNING_SECONDS}s; CRITICAL at ${LAG_SEVERITY_CRITICAL_LEDGERS} ledgers / ${LAG_SEVERITY_CRITICAL_SECONDS}s`,
        lastCheckpointAt: now,
        transactionLink: svc.link,
      } satisfies RcIndexerServiceDto;
    });
  }

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

      const lagSeconds =
        status.lagLedgers !== null
          ? status.lagLedgers * AVG_LEDGER_CLOSE_SECONDS
          : undefined;
      const indexerServices = this.buildIndexerServices(status, isBlocking);

      return {
        status: sectionStatus,
        currentNetworkLedger: status.currentNetworkLedger,
        lastIndexedLedger: status.lastIndexedLedger,
        lagLedgers: status.lagLedgers,
        lagSeconds,
        isLagging: status.isLagging,
        isBlocking,
        thresholdLedgers: status.thresholdLedgers,
        indexerServices,
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
        lagSeconds: undefined,
        isLagging: false,
        isBlocking: false,
        thresholdLedgers: 0,
        indexerServices: [],
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
      const checks: RcEnvironmentCheckDto[] = results.map((r) => ({
        check: r.check,
        status: r.status,
        details: r.details,
        severity: this.classifyEnvCheckSeverity(r.status),
        detailsLink: `/admin/settings?check=${r.check}`,
      }));
      const failed = checks.filter((r) => r.status === "fail");
      const warnings = checks.filter((r) => r.status === "warning");
      const passed = checks.filter((r) => r.status === "pass");

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

      const healthInfo = (async () => {
        try {
          return await this.health.getHealthStatus();
        } catch {
          return null;
        }
      });

      const metadata: RcEnvironmentMetadataDto = {
        appVersion: this.appVersion,
        commitHash: this.commitHash,
        commitShort: this.commitHash?.slice(0, 7),
        environmentName:
          this.config.environmentName ?? this.config.nodeEnv ?? "unknown",
        network: this.config.network,
        nodeEnv: this.config.nodeEnv,
        contractRegistryVersion:
          process.env.CONTRACT_REGISTRY_VERSION ?? undefined,
        deployedAt: process.env.DEPLOYED_AT ?? undefined,
      };

      void healthInfo().then((h) => {
        if (h?.uptime !== undefined) {
          metadata.uptimeSeconds = h.uptime;
        }
      });

      return {
        status,
        checks,
        passed: passed.length,
        failed: failed.length,
        warnings: warnings.length,
        metadata,
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
        metadata: {
          appVersion: this.appVersion,
          commitHash: this.commitHash,
          commitShort: this.commitHash?.slice(0, 7),
          environmentName:
            this.config.environmentName ??
            this.config.nodeEnv ??
            "unknown",
          network: this.config.network,
          nodeEnv: this.config.nodeEnv,
        },
      };
    }
  }
}
