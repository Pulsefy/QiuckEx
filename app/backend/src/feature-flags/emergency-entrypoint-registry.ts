/**
 * Emergency Entrypoint Registry
 *
 * Every public entrypoint that must be explicitly classified for emergency
 * mode is listed here with:
 *   - `status`: whether the route is ALLOWED or BLOCKED while emergency mode
 *     is active (i.e. any mainnet safety-gate flag has killSwitch=true or
 *     enabled=false on a fresh read).
 *   - `rationale`: human-readable explanation for the classification decision.
 *
 * ADDING A NEW ENTRYPOINT
 * -----------------------
 * 1. Decorate the handler with @EmergencyClassification('allowed'|'blocked').
 * 2. Add a corresponding entry in EMERGENCY_ENTRYPOINT_REGISTRY below.
 * 3. The exhaustiveness test in emergency-entrypoint-registry.unit.spec.ts will
 *    fail until both steps are completed.
 *
 * CLASSIFICATION RULES
 * ---------------------
 * BLOCKED  – mutating operations that interact with the Stellar network,
 *            Soroban contracts, or financial state (refunds, dispute actions,
 *            contract writes, backfill). These are the operations we want to
 *            halt during an incident.
 *
 * ALLOWED  – read-only queries, health checks, admin tooling that does not
 *            itself initiate writes to the ledger, and flag management endpoints
 *            that are needed to *lift* an emergency. Blocking these during an
 *            incident would prevent operators from recovering.
 */

import { SetMetadata } from "@nestjs/common";

// ── Metadata key ──────────────────────────────────────────────────────────────

export const EMERGENCY_CLASSIFICATION_KEY = "emergency_classification";

export type EmergencyStatus = "allowed" | "blocked";

/**
 * Decorator: explicitly classify an entrypoint for emergency mode.
 *
 * @param status  'allowed' — route proceeds normally during emergency.
 *                'blocked' — route is rejected with EMERGENCY_MODE_ACTIVE.
 * @param rationale  One-sentence justification, recorded in the registry and
 *                   surfaced in test output.
 */
export const EmergencyClassification = (
  status: EmergencyStatus,
  rationale: string,
) => SetMetadata(EMERGENCY_CLASSIFICATION_KEY, { status, rationale });

// ── Registry ──────────────────────────────────────────────────────────────────

/**
 * Canonical record type for one entrypoint classification.
 *
 * `controller` and `handler` identify the TypeScript class + method name so
 * the exhaustiveness test can verify decorator presence via reflection without
 * spinning up the full NestJS DI container.
 */
export interface EntrypointClassification {
  /** Human-readable label used in test descriptions and error output. */
  label: string;
  /** The controller class (used by the spec for reflection). */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  controllerClass: new (...args: any[]) => object;
  /** The method name on the controller prototype. */
  handlerName: string;
  status: EmergencyStatus;
  rationale: string;
}

// Lazy imports — we import the controller classes only here so the registry
// can be imported in tests without pulling the full NestJS module graph.
const { TransactionsController } =
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  require("../transactions/transactions.controller") as typeof import("../transactions/transactions.controller");
const { StellarController } =
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  require("../stellar/stellar.controller") as typeof import("../stellar/stellar.controller");
const { RefundsController } =
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  require("../refunds/refunds.controller") as typeof import("../refunds/refunds.controller");
const { ReconciliationController } =
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  require("../reconciliation/reconciliation.controller") as typeof import("../reconciliation/reconciliation.controller");

/**
 * The authoritative list of every entrypoint that requires an explicit
 * emergency classification.
 *
 * RULE: only routes that carry @EmergencyClassification *and* are
 * NetworkSafetyGuard-protected (or are high-value admin mutations) need to
 * appear here. Pure read-only infrastructure endpoints (health, metrics,
 * feature-flag snapshot reads) do not require classification because the guard
 * itself passes them through unconditionally.
 *
 * When you add a new route protected by NetworkSafetyGuard, add it here too.
 * The spec will catch any omission.
 */
export const EMERGENCY_ENTRYPOINT_REGISTRY: EntrypointClassification[] = [
  // ── Transactions ────────────────────────────────────────────────────────────
  {
    label: "POST /transactions/compose",
    controllerClass: TransactionsController,
    handlerName: "compose",
    status: "blocked",
    rationale:
      "Composes a Soroban contract write transaction; must be halted during an incident " +
      "to prevent new on-chain mutations while the network is in an unsafe state.",
  },
  {
    label: "POST /transactions/build",
    controllerClass: TransactionsController,
    handlerName: "buildUnsignedXdr",
    status: "blocked",
    rationale:
      "Builds unsigned Soroban XDR; functionally equivalent to compose — same write " +
      "pipeline, same risk surface during an incident.",
  },
  {
    label: "POST /transactions/simulate",
    controllerClass: TransactionsController,
    handlerName: "simulateOperation",
    status: "blocked",
    rationale:
      "Simulates contract operations via the Soroban RPC; while read-like in intent, " +
      "simulation submits to the RPC network and must stop when the kill switch fires.",
  },
  {
    label: "POST /transactions/submit",
    controllerClass: TransactionsController,
    handlerName: "submitSignedTransaction",
    status: "blocked",
    rationale:
      "Submits a signed transaction to the Stellar network — the highest-risk write " +
      "operation; must be blocked immediately when emergency mode activates.",
  },
  {
    label: "GET /transactions",
    controllerClass: TransactionsController,
    handlerName: "getTransactions",
    status: "allowed",
    rationale:
      "Read-only Horizon fetch; does not mutate any state and is needed during an " +
      "incident for operators to inspect payment history.",
  },

  // ── Stellar ─────────────────────────────────────────────────────────────────
  {
    label: "POST /stellar/soroban-preflight",
    controllerClass: StellarController,
    handlerName: "sorobanPreflight",
    status: "blocked",
    rationale:
      "Runs the Soroban composer pipeline against the live contract; blocked during " +
      "emergency for the same reason as compose/build.",
  },
  {
    label: "GET /stellar/verified-assets",
    controllerClass: StellarController,
    handlerName: "getVerifiedAssets",
    status: "allowed",
    rationale:
      "Returns static asset metadata from TOML files; purely informational and " +
      "required for front-end rendering during an incident.",
  },
  {
    label: "POST /stellar/path-preview",
    controllerClass: StellarController,
    handlerName: "pathPreview",
    status: "allowed",
    rationale:
      "Read-only Horizon path-payment query; no state mutation and needed for " +
      "quote display while an incident is in progress.",
  },
  {
    label: "POST /stellar/path-preview/strict-send",
    controllerClass: StellarController,
    handlerName: "strictSendPathPreview",
    status: "allowed",
    rationale:
      "Read-only Horizon strict-send path query; same reasoning as pathPreview.",
  },
  {
    label: "POST /stellar/quote",
    controllerClass: StellarController,
    handlerName: "createQuote",
    status: "allowed",
    rationale:
      "Creates an in-memory quote; does not write to the ledger and must stay " +
      "available so users can see pricing during an incident.",
  },
  {
    label: "GET /stellar/quote/:quoteId",
    controllerClass: StellarController,
    handlerName: "getQuote",
    status: "allowed",
    rationale: "Read-only quote retrieval; no ledger interaction.",
  },

  // ── Refunds ─────────────────────────────────────────────────────────────────
  {
    label: "POST /admin/refunds/check-eligibility",
    controllerClass: RefundsController,
    handlerName: "checkEligibility",
    status: "allowed",
    rationale:
      "Audit-only check that reads state without initiating a refund; operators " +
      "need this during an incident to triage which payments are affected.",
  },
  {
    label: "POST /admin/refunds",
    controllerClass: RefundsController,
    handlerName: "initiate",
    status: "blocked",
    rationale:
      "Initiates a refund on mainnet — a contract write; must be halted while the " +
      "network safety gate is active.",
  },
  {
    label: "POST /admin/refunds/:id/approve",
    controllerClass: RefundsController,
    handlerName: "approve",
    status: "blocked",
    rationale:
      "Approves and executes a pending refund on mainnet; same write-path risk as initiate.",
  },
  {
    label: "POST /admin/refunds/:id/reject",
    controllerClass: RefundsController,
    handlerName: "reject",
    status: "blocked",
    rationale:
      "Rejects a pending refund — mutates refund state; blocked during emergency to " +
      "preserve a stable audit trail until the incident is resolved.",
  },
  {
    label: "GET /admin/refunds",
    controllerClass: RefundsController,
    handlerName: "list",
    status: "allowed",
    rationale:
      "Read-only list of refund attempts; operators need visibility into pending " +
      "refunds during an incident.",
  },

  // ── Reconciliation ──────────────────────────────────────────────────────────
  {
    label: "POST /reconciliation/backfill",
    controllerClass: ReconciliationController,
    handlerName: "startBackfill",
    status: "blocked",
    rationale:
      "Triggers a ledger backfill that writes contract state; gated by " +
      "mainnet.contract_writes and must stop during an incident.",
  },
  {
    label: "GET /reconciliation/status",
    controllerClass: ReconciliationController,
    handlerName: "getStatus",
    status: "allowed",
    rationale:
      "Read-only worker status; operators must be able to observe reconciliation " +
      "state throughout an incident.",
  },
  {
    label: "POST /reconciliation/trigger",
    controllerClass: ReconciliationController,
    handlerName: "trigger",
    status: "allowed",
    rationale:
      "Triggers a reconciliation *read* cycle — the worker reads on-chain state " +
      "and produces a drift report without writing; safe during an incident.",
  },
  {
    label: "GET /reconciliation/backfill/status",
    controllerClass: ReconciliationController,
    handlerName: "getBackfillStatus",
    status: "allowed",
    rationale: "Read-only progress snapshot; no state mutation.",
  },
  {
    label: "GET /reconciliation/auto-match/status",
    controllerClass: ReconciliationController,
    handlerName: "getAutoMatchStatus",
    status: "allowed",
    rationale: "Read-only engine status; no state mutation.",
  },
  {
    label: "POST /reconciliation/auto-match/trigger",
    controllerClass: ReconciliationController,
    handlerName: "triggerAutoMatch",
    status: "allowed",
    rationale:
      "Runs the in-process matching algorithm against already-indexed data; " +
      "does not submit transactions to the ledger.",
  },
  {
    label: "POST /reconciliation/auto-match/process",
    controllerClass: ReconciliationController,
    handlerName: "processTransaction",
    status: "allowed",
    rationale:
      "Scores a single transaction locally; read/compute only, no ledger interaction.",
  },
  {
    label: "GET /reconciliation/history",
    controllerClass: ReconciliationController,
    handlerName: "listHistory",
    status: "allowed",
    rationale: "Read-only run history; no state mutation.",
  },
  {
    label: "GET /reconciliation/history/:runId",
    controllerClass: ReconciliationController,
    handlerName: "getRun",
    status: "allowed",
    rationale: "Read-only single-run detail; no state mutation.",
  },
  {
    label: "GET /reconciliation/unmatched",
    controllerClass: ReconciliationController,
    handlerName: "listUnmatched",
    status: "allowed",
    rationale: "Read-only unmatched queue list; no state mutation.",
  },
  {
    label: "GET /reconciliation/unmatched/:id",
    controllerClass: ReconciliationController,
    handlerName: "getUnmatched",
    status: "allowed",
    rationale: "Read-only single unmatched transaction; no state mutation.",
  },
  {
    label: "POST /reconciliation/unmatched/:id/resolve",
    controllerClass: ReconciliationController,
    handlerName: "resolveUnmatched",
    status: "allowed",
    rationale:
      "Marks an unmatched transaction as manually resolved in the database " +
      "(no ledger write); operators must be able to triage the queue during an incident.",
  },
  {
    label: "DELETE /reconciliation/unmatched/:id",
    controllerClass: ReconciliationController,
    handlerName: "dismissUnmatched",
    status: "allowed",
    rationale:
      "Dismisses an unmatched transaction record in the database (no ledger write); " +
      "same triage reasoning as resolve.",
  },
];

/**
 * Build a lookup map from `controllerClass.prototype + handlerName` → classification.
 * Used by the guard and the tests.
 */
export function buildRegistryIndex(
  registry: EntrypointClassification[],
): Map<string, EntrypointClassification> {
  const index = new Map<string, EntrypointClassification>();
  for (const entry of registry) {
    const key = registryKey(entry.controllerClass, entry.handlerName);
    index.set(key, entry);
  }
  return index;
}

/**
 * Stable string key derived from a controller class + method name.
 * Used to correlate the registry with NestJS ExecutionContext metadata.
 */
export function registryKey(
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  controllerClass: new (...args: any[]) => object,
  handlerName: string,
): string {
  return `${controllerClass.name}#${handlerName}`;
}
