/**
 * deployment-info.ts
 *
 * Collects deployment metadata from runtime environment variables.
 * All values come from process.env – nothing is hardcoded.
 *
 * Vercel injects the following at build time for Preview and Production:
 *   NEXT_PUBLIC_VERCEL_GIT_COMMIT_REF   – branch name
 *   NEXT_PUBLIC_VERCEL_GIT_COMMIT_SHA   – full commit SHA
 *   NEXT_PUBLIC_VERCEL_ENV              – "production" | "preview" | "development"
 *   NEXT_PUBLIC_VERCEL_URL              – deployment URL (no protocol)
 *
 * NEXT_PUBLIC_VERCEL_DEPLOYED_AT should be set in the GitHub Actions
 * deploy workflow (e.g. `echo "NEXT_PUBLIC_VERCEL_DEPLOYED_AT=$(date -u +%FT%TZ)"`)
 * so contributors can see when the build was stamped.
 *
 * NEXT_PUBLIC_CONTRACT_REGISTRY_VERSION should be injected by the contract
 * deploy CI step (see app/contract/scripts/deploy.sh).
 */

export interface DeploymentInfo {
  /** Git branch name, e.g. "feat/preview-diagnostics" */
  branch: string | null;
  /** Full 40-char commit SHA */
  commitSha: string | null;
  /** Short (7-char) commit SHA derived from commitSha */
  commitShort: string | null;
  /** ISO-8601 timestamp of when this build was deployed */
  deployedAt: string | null;
  /** Backend API base URL */
  apiUrl: string;
  /** Stellar network: "testnet" or "mainnet" */
  network: string;
  /** Vercel environment tier: "production" | "preview" | "development" | null */
  vercelEnv: string | null;
  /** Full deployment URL provided by Vercel (no protocol) */
  vercelUrl: string | null;
  /** Contract registry version string injected by CI during contract deploy */
  contractRegistryVersion: string | null;
  /** App version string */
  appVersion: string | null;
}

/**
 * Returns deployment metadata derived purely from runtime environment
 * variables. Safe to call from both client and server components.
 */
export function getDeploymentInfo(): DeploymentInfo {
  const commitSha =
    process.env.NEXT_PUBLIC_VERCEL_GIT_COMMIT_SHA ?? null;

  return {
    branch:
      process.env.NEXT_PUBLIC_VERCEL_GIT_COMMIT_REF ?? null,
    commitSha,
    commitShort: commitSha ? commitSha.slice(0, 7) : null,
    deployedAt:
      process.env.NEXT_PUBLIC_VERCEL_DEPLOYED_AT ?? null,
    apiUrl:
      (process.env.NEXT_PUBLIC_QUICKEX_API_URL ?? "http://localhost:4000").replace(
        /\/$/,
        "",
      ),
    network:
      process.env.NEXT_PUBLIC_STELLAR_NETWORK ?? "testnet",
    vercelEnv:
      process.env.NEXT_PUBLIC_VERCEL_ENV ?? null,
    vercelUrl:
      process.env.NEXT_PUBLIC_VERCEL_URL ?? null,
    contractRegistryVersion:
      process.env.NEXT_PUBLIC_CONTRACT_REGISTRY_VERSION ?? null,
    appVersion:
      process.env.NEXT_PUBLIC_APP_VERSION ?? null,
  };
}

/**
 * Returns true when the diagnostics panel should be visible.
 *
 * Hidden only when both of these are true:
 *   - Vercel environment is "production"
 *   - Stellar network is "mainnet"
 *
 * This keeps the panel out of real end-user deployments while always
 * showing it in preview branches, testnet, and local dev.
 */
export function isDiagnosticsPanelVisible(info: DeploymentInfo): boolean {
  const isProductionVercel = info.vercelEnv === "production";
  const isMainnet = info.network === "mainnet";
  return !(isProductionVercel && isMainnet);
}
