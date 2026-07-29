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

  @ApiProperty({ example: false })
  isLagging!: boolean;

  @ApiProperty({
    description: "Whether the indexer-lag guard would block traffic",
    example: false,
  })
  isBlocking!: boolean;

  @ApiProperty({ example: 100 })
  thresholdLedgers!: number;
}

export class RcEnvironmentCheckDto {
  @ApiProperty({ example: "network_configuration" })
  check!: string;

  @ApiProperty({ enum: ["pass", "fail", "warning"], example: "pass" })
  status!: "pass" | "fail" | "warning";

  @ApiProperty({ required: false, example: "Network: testnet" })
  details?: string;
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
