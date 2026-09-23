export type Severity = "critical" | "warning" | "info" | "healthy";

export type SectionStatus = "pass" | "warning" | "fail" | "unknown";

export type OverallStatus = "ready" | "degraded" | "blocked";

export type BlockerCategory = "smoke" | "registry" | "lag" | "environment";

export type SmokeCategory =
  | "health"
  | "network"
  | "links"
  | "soroban"
  | "horizon"
  | "performance";

export interface Blocker {
  id: string;
  severity: "critical" | "warning" | "info";
  category: BlockerCategory;
  message: string;
  remediation?: string;
  detectedAt: string;
}

export interface SmokeCheck {
  name: string;
  status: "up" | "down";
  error?: string;
  category?: SmokeCategory;
  durationMs?: number;
  lastRunAt?: string;
  transactionLink?: string;
  webhookLink?: string;
}

export interface SmokeSection {
  status: SectionStatus;
  ready: boolean;
  checks: SmokeCheck[];
  passed: number;
  failed: number;
  skipped?: number;
  totalDurationMs?: number;
  lastRunAt?: string;
  failureDetails?: string[];
}

export interface RegistryContractDetail {
  name: string;
  contractStatus: "active" | "missing" | "mismatched" | "inactive";
  severity: Severity;
  contractId?: string;
  wasmHash?: string;
  contractVersion?: number;
  schemaVersion?: string;
  updatedAt?: string;
  publishedBy?: string;
  networkPassphraseMatches?: boolean;
  expectedPassphrase?: string;
  actualPassphrase?: string;
  registryLink?: string;
  webhookLink?: string;
}

export interface RegistrySection {
  status: SectionStatus;
  network: string;
  authoritative: boolean;
  version: number;
  activeContracts: number;
  expectedContracts: string[];
  missingContracts: string[];
  contractDetails?: RegistryContractDetail[];
  mismatchedContracts?: number;
}

export interface IndexerService {
  serviceName: string;
  severity: Severity;
  currentNetworkLedger: number | null;
  lastIndexedLedger: number | null;
  lagLedgers: number | null;
  lagSeconds?: number;
  isLagging: boolean;
  isBlocking: boolean;
  thresholdLedgers: number;
  thresholdDescription?: string;
  lastCheckpointAt?: string;
  transactionLink?: string;
}

export interface LagSection {
  status: SectionStatus;
  currentNetworkLedger: number | null;
  lastIndexedLedger: number | null;
  lagLedgers: number | null;
  lagSeconds?: number;
  isLagging: boolean;
  isBlocking: boolean;
  thresholdLedgers: number;
  indexerServices?: IndexerService[];
}

export interface EnvironmentCheck {
  check: string;
  status: "pass" | "fail" | "warning";
  details?: string;
  severity?: Severity;
  detailsLink?: string;
}

export interface EnvironmentMetadata {
  appVersion: string;
  commitHash?: string;
  commitShort?: string;
  environmentName: string;
  network: string;
  nodeEnv?: string;
  uptimeSeconds?: number;
  deployedAt?: string;
  contractRegistryVersion?: string;
}

export interface EnvironmentSection {
  status: SectionStatus;
  checks: EnvironmentCheck[];
  passed: number;
  failed: number;
  warnings: number;
  metadata?: EnvironmentMetadata;
}

export interface HealthSections {
  smoke: SmokeSection;
  registry: RegistrySection;
  lag: LagSection;
  environment: EnvironmentSection;
}

export interface HealthReport {
  reportId: string;
  generatedAt: string;
  network: string;
  environment: string;
  releaseReady: boolean;
  overallStatus: OverallStatus;
  sections: HealthSections;
  blockers: Blocker[];
  summary: {
    critical: number;
    warning: number;
    info: number;
  };
}
