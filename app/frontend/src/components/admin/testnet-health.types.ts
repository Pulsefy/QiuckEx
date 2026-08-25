/**
 * Shared types for the Admin Testnet Health Console (FE-46).
 * Mirrors `app/backend/src/rc-validation/dto/rc-report.dto.ts` and the
 * contract registry deployment DTOs so console rendering stays in sync
 * with the backend API contracts.
 */

export type RcBlockerSeverity = "critical" | "warning" | "info";

export type RcBlockerCategory = "smoke" | "registry" | "lag" | "environment";

export type RcSectionStatus = "pass" | "warning" | "fail" | "unknown";

export type RcOverallStatus = "ready" | "degraded" | "blocked";

export interface RcBlocker {
  id: string;
  severity: RcBlockerSeverity;
  category: RcBlockerCategory;
  message: string;
  remediation?: string;
  detectedAt: string;
}

export interface RcSmokeCheck {
  name: string;
  status: "up" | "degraded" | "down";
  error?: string;
}

export interface RcSmokeSection {
  status: RcSectionStatus;
  ready: boolean;
  checks: RcSmokeCheck[];
  passed: number;
  failed: number;
}

export interface RcRegistrySection {
  status: RcSectionStatus;
  network: string;
  authoritative: boolean;
  version: number;
  activeContracts: number;
  expectedContracts: string[];
  missingContracts: string[];
}

export interface RcLagSection {
  status: RcSectionStatus;
  currentNetworkLedger: number | null;
  lastIndexedLedger: number | null;
  lagLedgers: number | null;
  isLagging: boolean;
  isBlocking: boolean;
  thresholdLedgers: number;
}

export interface RcEnvironmentCheck {
  check: string;
  status: "pass" | "fail" | "warning";
  details?: string;
}

export interface RcEnvironmentSection {
  status: RcSectionStatus;
  checks: RcEnvironmentCheck[];
  passed: number;
  failed: number;
  warnings: number;
}

export interface RcValidationReport {
  reportId: string;
  generatedAt: string;
  network: string;
  environment: string;
  releaseReady: boolean;
  overallStatus: RcOverallStatus;
  sections: {
    smoke: RcSmokeSection;
    registry: RcRegistrySection;
    lag: RcLagSection;
    environment: RcEnvironmentSection;
  };
  blockers: RcBlocker[];
  summary: {
    critical: number;
    warning: number;
    info: number;
  };
}

export interface ContractSchemaCompatibility {
  min: string;
  max: string;
}

export interface ContractDeploymentItem {
  name: string;
  network: string;
  networkPassphrase?: string;
  contractId: string;
  wasmHash: string;
  contractVersion: number;
  schemaVersion: string;
  schemaCompatibility?: ContractSchemaCompatibility;
  initParams?: Record<string, unknown>;
  metadata?: Record<string, unknown>;
  updatedAt: string;
  registryVersion: number;
  deploymentId?: string;
}

export interface ContractDeploymentsResponse {
  network: string;
  deployments: ContractDeploymentItem[];
}

export type SeverityFilter = "all" | RcBlockerSeverity;
