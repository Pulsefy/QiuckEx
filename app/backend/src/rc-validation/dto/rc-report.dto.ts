import { ApiProperty } from "@nestjs/swagger";

/**
 * Severity classification for a release-candidate blocker.
 *
 * - `critical`: must be resolved before the RC can ship. Maps to a failed
 *   smoke check, a missing/incorrect contract registry, or a blocking indexer lag.
 * - `warning`: should be reviewed but does not strictly block the release.
 * - `info`: advisory signal an operator may want to be aware of.
 */
export type RcBlockerSeverity = "critical" | "warning" | "info";

/**
 * Which aggregated section a blocker originated from.
 */
export type RcBlockerCategory =
  | "smoke"
  | "registry"
  | "lag"
  | "environment";

/**
 * Section-level health status. `unknown` is used when a source could not be
 * evaluated (e.g. it threw), which keeps partial reports renderable.
 */
export type RcSectionStatus = "pass" | "warning" | "fail" | "unknown";

/**
 * Overall release-candidate readiness.
 *
 * - `ready`: no critical blockers.
 * - `degraded`: only warning/info blockers present.
 * - `blocked`: at least one critical blocker present.
 */
export type RcOverallStatus = "ready" | "degraded" | "blocked";

export class RcBlockerDto {
  @ApiProperty({
    description: "Stable identifier for the blocker within a report",
    example: "smoke.horizon.down",
  })
  id!: string;

  @ApiProperty({
    description: "Severity classification",
    enum: ["critical", "warning", "info"],
    example: "critical",
  })
  severity!: RcBlockerSeverity;

  @ApiProperty({
    description: "Aggregated section the blocker came from",
    enum: ["smoke", "registry", "lag", "environment"],
    example: "smoke",
  })
  category!: RcBlockerCategory;

  @ApiProperty({
    description: "Operator-friendly description of the blocker",
    example: "Critical dependency 'horizon' is down",
  })
  message!: string;

  @ApiProperty({
    description: "Suggested remediation for the operator",
    example: "Verify Horizon connectivity and restart ingestion if needed",
    required: false,
  })
  remediation?: string;

  @ApiProperty({
    description: "ISO-8601 timestamp the blocker was detected",
    example: "2026-06-27T12:00:00.000Z",
  })
  detectedAt!: string;
}

export class RcSmokeCheckDto {
  @ApiProperty({ example: "horizon" })
  name!: string;

  @ApiProperty({ enum: ["up", "down"], example: "up" })
  status!: "up" | "down";

  @ApiProperty({ required: false, example: "Horizon returned 503" })
  error?: string;

  @ApiProperty({
    enum: ["health", "network", "links", "soroban", "horizon", "performance"],
    example: "horizon",
    required: false,
  })
  category?: "health" | "network" | "links" | "soroban" | "horizon" | "performance";

  @ApiProperty({ required: false, example: 42 })
  durationMs?: number;

  @ApiProperty({ required: false, example: "2026-06-27T12:00:00.000Z" })
  lastRunAt?: string;

  @ApiProperty({
    description: "Route for transaction details (if applicable)",
    example: "/transactions/abc123",
    required: false,
  })
  transactionLink?: string;

  @ApiProperty({
    description: "Route for webhook logs (if applicable)",
    example: "/webhooks?test=horizon",
    required: false,
  })
  webhookLink?: string;
}

export class RcSmokeSectionDto {
  @ApiProperty({ enum: ["pass", "warning", "fail", "unknown"] })
  status!: RcSectionStatus;

  @ApiProperty({
    description: "Whether all critical readiness probes passed",
    example: true,
  })
  ready!: boolean;

  @ApiProperty({ type: [RcSmokeCheckDto] })
  checks!: RcSmokeCheckDto[];

  @ApiProperty({ example: 6 })
  passed!: number;

  @ApiProperty({ example: 0 })
  failed!: number;

  @ApiProperty({ example: 1, required: false })
  skipped?: number;

  @ApiProperty({ example: 142, required: false })
  totalDurationMs?: number;

  @ApiProperty({ example: "2026-06-27T12:00:00.000Z", required: false })
  lastRunAt?: string;

  @ApiProperty({ type: [String], required: false, example: [] })
  failureDetails?: string[];
}

export class RcRegistryContractDetailDto {
  @ApiProperty({ example: "quickex" })
  name!: string;

  @ApiProperty({
    enum: ["active", "missing", "mismatched", "inactive"],
    example: "active",
  })
  contractStatus!: "active" | "missing" | "mismatched" | "inactive";

  @ApiProperty({
    enum: ["critical", "warning", "info", "healthy"],
    example: "healthy",
  })
  severity!: "critical" | "warning" | "info" | "healthy";

  @ApiProperty({
    example: "CCNGBQ7R...",
    required: false,
  })
  contractId?: string;

  @ApiProperty({ example: "a1b2c3d4...", required: false })
  wasmHash?: string;

  @ApiProperty({ example: 3, required: false })
  contractVersion?: number;

  @ApiProperty({ example: "2.1.0", required: false })
  schemaVersion?: string;

  @ApiProperty({ example: "2026-06-27T12:00:00.000Z", required: false })
  updatedAt?: string;

  @ApiProperty({ example: "deploy_user", required: false })
  publishedBy?: string;

  @ApiProperty({ example: true, required: false })
  networkPassphraseMatches?: boolean;

  @ApiProperty({ example: "Test SDF Network...", required: false })
  expectedPassphrase?: string;

  @ApiProperty({ example: "Test SDF Network...", required: false })
  actualPassphrase?: string;

  @ApiProperty({
    example: "/admin/registry/quickex",
    required: false,
  })
  registryLink?: string;

  @ApiProperty({
    example: "/webhooks?contract=quickex",
    required: false,
  })
  webhookLink?: string;
}

export class RcRegistrySectionDto {
  @ApiProperty({ enum: ["pass", "warning", "fail", "unknown"] })
  status!: RcSectionStatus;

  @ApiProperty({ example: "testnet" })
  network!: string;

  @ApiProperty({
    description: "Whether the registry is the authoritative source",
    example: true,
  })
  authoritative!: boolean;

  @ApiProperty({ example: 3 })
  version!: number;

  @ApiProperty({
    description: "Number of active (deployed) contract entries",
    example: 1,
  })
  activeContracts!: number;

  @ApiProperty({
    description: "Contracts expected to be present for this release",
    example: ["quickex"],
  })
  expectedContracts!: string[];

  @ApiProperty({
    description: "Expected contracts that are missing from the registry",
    example: [],
  })
  missingContracts!: string[];

  @ApiProperty({ type: [RcRegistryContractDetailDto], required: false })
  contractDetails?: RcRegistryContractDetailDto[];

  @ApiProperty({ example: 0, required: false })
  mismatchedContracts?: number;
}

export class RcIndexerServiceDto {
  @ApiProperty({ example: "contract-events" })
  serviceName!: string;

  @ApiProperty({
    enum: ["critical", "warning", "info", "healthy"],
    example: "healthy",
  })
  severity!: "critical" | "warning" | "info" | "healthy";

  @ApiProperty({ nullable: true, example: 123456 })
  currentNetworkLedger!: number | null;

  @ApiProperty({ nullable: true, example: 123450 })
  lastIndexedLedger!: number | null;

  @ApiProperty({ nullable: true, example: 6 })
  lagLedgers!: number | null;

  @ApiProperty({
    description: "Estimated lag in seconds (avg 5s ledger close)",
    example: 30,
    required: false,
  })
  lagSeconds?: number;

  @ApiProperty({ example: false })
  isLagging!: boolean;

  @ApiProperty({ example: false })
  isBlocking!: boolean;

  @ApiProperty({ example: 100 })
  thresholdLedgers!: number;

  @ApiProperty({
    example: "500 ledgers / 2500 seconds for CRITICAL",
    required: false,
  })
  thresholdDescription?: string;

  @ApiProperty({ example: "2026-06-27T12:00:00.000Z", required: false })
  lastCheckpointAt?: string;

  @ApiProperty({
    example: "/transactions?service=contract-events",
    required: false,
  })
  transactionLink?: string;
}

export class RcLagSectionDto {
  @ApiProperty({ enum: ["pass", "warning", "fail", "unknown"] })
  status!: RcSectionStatus;

  @ApiProperty({ nullable: true, example: 123456 })
  currentNetworkLedger!: number | null;

  @ApiProperty({ nullable: true, example: 123450 })
  lastIndexedLedger!: number | null;

  @ApiProperty({ nullable: true, example: 6 })
  lagLedgers!: number | null;

  @ApiProperty({
    description: "Estimated aggregate lag in seconds",
    example: 30,
    required: false,
  })
  lagSeconds?: number;

  @ApiProperty({ example: false })
  isLagging!: boolean;

  @ApiProperty({
    description: "Whether the indexer-lag guard would block traffic",
    example: false,
  })
  isBlocking!: boolean;

  @ApiProperty({ example: 100 })
  thresholdLedgers!: number;

  @ApiProperty({ type: [RcIndexerServiceDto], required: false })
  indexerServices?: RcIndexerServiceDto[];
}

export class RcEnvironmentCheckDto {
  @ApiProperty({ example: "network_configuration" })
  check!: string;

  @ApiProperty({ enum: ["pass", "fail", "warning"], example: "pass" })
  status!: "pass" | "fail" | "warning";

  @ApiProperty({ required: false, example: "Network: testnet" })
  details?: string;

  @ApiProperty({
    enum: ["critical", "warning", "info", "healthy"],
    example: "healthy",
    required: false,
  })
  severity?: "critical" | "warning" | "info" | "healthy";

  @ApiProperty({
    example: "/admin/settings?check=network_configuration",
    required: false,
  })
  detailsLink?: string;
}

export class RcEnvironmentMetadataDto {
  @ApiProperty({ example: "0.1.0" })
  appVersion!: string;

  @ApiProperty({ example: "abcdef1234567890abcdef1234567890abcdef12", required: false })
  commitHash?: string;

  @ApiProperty({ example: "abcdef1", required: false })
  commitShort?: string;

  @ApiProperty({ example: "staging" })
  environmentName!: string;

  @ApiProperty({ example: "testnet" })
  network!: string;

  @ApiProperty({ example: "production", required: false })
  nodeEnv?: string;

  @ApiProperty({ example: 1842, required: false })
  uptimeSeconds?: number;

  @ApiProperty({ example: "2026-06-27T12:00:00.000Z", required: false })
  deployedAt?: string;

  @ApiProperty({ example: "3", required: false })
  contractRegistryVersion?: string;
}

export class RcEnvironmentSectionDto {
  @ApiProperty({ enum: ["pass", "warning", "fail", "unknown"] })
  status!: RcSectionStatus;

  @ApiProperty({ type: [RcEnvironmentCheckDto] })
  checks!: RcEnvironmentCheckDto[];

  @ApiProperty({ example: 7 })
  passed!: number;

  @ApiProperty({ example: 0 })
  failed!: number;

  @ApiProperty({ example: 0 })
  warnings!: number;

  @ApiProperty({ type: RcEnvironmentMetadataDto, required: false })
  metadata?: RcEnvironmentMetadataDto;
}

export class RcSectionsDto {
  @ApiProperty({ type: RcSmokeSectionDto })
  smoke!: RcSmokeSectionDto;

  @ApiProperty({ type: RcRegistrySectionDto })
  registry!: RcRegistrySectionDto;

  @ApiProperty({ type: RcLagSectionDto })
  lag!: RcLagSectionDto;

  @ApiProperty({ type: RcEnvironmentSectionDto })
  environment!: RcEnvironmentSectionDto;
}

export class RcBlockerSummaryDto {
  @ApiProperty({ example: 0 })
  critical!: number;

  @ApiProperty({ example: 1 })
  warning!: number;

  @ApiProperty({ example: 2 })
  info!: number;
}

export class RcValidationReportDto {
  @ApiProperty({
    description: "Unique identifier for this report instance",
    example: "5f0c2c2e-2a3b-4d8e-9c1a-1f2e3d4c5b6a",
  })
  reportId!: string;

  @ApiProperty({
    description: "ISO-8601 timestamp the report was generated",
    example: "2026-06-27T12:00:00.000Z",
  })
  generatedAt!: string;

  @ApiProperty({ example: "testnet" })
  network!: string;

  @ApiProperty({ example: "staging" })
  environment!: string;

  @ApiProperty({
    description: "True when there are no critical blockers",
    example: true,
  })
  releaseReady!: boolean;

  @ApiProperty({
    description: "Overall readiness derived from blocker severities",
    enum: ["ready", "degraded", "blocked"],
    example: "degraded",
  })
  overallStatus!: RcOverallStatus;

  @ApiProperty({ type: RcSectionsDto })
  sections!: RcSectionsDto;

  @ApiProperty({ type: [RcBlockerDto] })
  blockers!: RcBlockerDto[];

  @ApiProperty({ type: RcBlockerSummaryDto })
  summary!: RcBlockerSummaryDto;
}
