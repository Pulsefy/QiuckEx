/**
 * Metrics – Label Cardinality Protection
 *
 * ## Why this exists
 * Prometheus performance degrades sharply when a metric's label-set grows
 * without bound ("cardinality explosion"). Common culprits are labels that
 * accept free-form strings from user-controlled input: payment IDs, usernames,
 * contract addresses, endpoint URLs, etc.
 *
 * ## How to add a new metric safely
 * 1. Identify every `labelNames` entry that could receive user-controlled or
 *    dynamically-generated values.
 * 2. For each such label, define or reuse an allowlist constant below.
 * 3. Wrap the raw value with `sanitizeLabel(value, ALLOWLIST)` at the call
 *    site in `MetricsService` before passing it to `.labels()`.
 * 4. Add a unit test that calls `sanitizeLabel` with an unknown value and
 *    asserts the result is `"other"`.
 *
 * Labels that only ever receive a small, compile-time-fixed set of values
 * (e.g. `method: "GET" | "POST"`, `outcome: "success" | "retry" | "dead"`)
 * do NOT need an allowlist — their cardinality is inherently bounded.
 *
 * ## Overflow bucket
 * Unknown values are mapped to the sentinel string `"other"`.  This keeps
 * cardinality bounded while still letting you detect anomalous inputs via the
 * `{label="other"}` series in dashboards / alerts.
 */

/** Sentinel value used when an incoming label value is not in the allowlist. */
export const LABEL_OVERFLOW = "other" as const;

/**
 * Clamp `value` to the provided `allowlist`.
 * Returns `value` unchanged if it is in the list; returns `LABEL_OVERFLOW`
 * ("other") otherwise.
 *
 * @example
 * sanitizeLabel("EscrowDeposited", ALLOWED_EVENT_TYPES) // → "EscrowDeposited"
 * sanitizeLabel("user-1234-secret", ALLOWED_EVENT_TYPES) // → "other"
 */
export function sanitizeLabel(value: string, allowlist: readonly string[]): string {
  return allowlist.includes(value) ? value : LABEL_OVERFLOW;
}

// ---------------------------------------------------------------------------
// Per-dimension allowlists
// ---------------------------------------------------------------------------

/**
 * Allowlist for `event_type` labels (webhook retry / delivery / outbox).
 * Keep in sync with `NotificationEventType` in notification.types.ts.
 */
export const ALLOWED_EVENT_TYPES = [
  "EscrowDeposited",
  "EscrowWithdrawn",
  "EscrowRefunded",
  "payment.received",
  "username.claimed",
  "recurring.payment.due",
  "recurring.payment.executed",
  "recurring.payment.failed",
  "recurring.payment.cancelled",
  "recurring.link.created",
  "recurring.link.updated",
  "recurring.link.paused",
  "recurring.link.resumed",
  "recurring.link.completed",
  "auto_reconciliation.succeeded",
  "payment.link.expired",
  "export.completed",
  "export.failed",
] as const;

/**
 * Allowlist for `status` labels used on webhook metrics.
 */
export const ALLOWED_WEBHOOK_STATUSES = [
  "success",
  "failed",
  "retrying",
  "dropped",
] as const;

/**
 * Allowlist for `reason` labels on Soroban RPC failover metrics.
 * Populated from the finite set of reasons emitted by SorobanRpcService.
 */
export const ALLOWED_RPC_FAILOVER_REASONS = [
  "network timeout",
  "503 unavailable",
  "connection refused",
  "invalid response",
  "circuit open",
] as const;

/**
 * Allowlist for `event_name` labels on the unknown-schema-version counter.
 * These are the contract event names the indexer recognises.
 */
export const ALLOWED_EVENT_NAMES = [
  "EscrowDeposited",
  "EscrowWithdrawn",
  "EscrowRefunded",
  "RecurringPaymentExecuted",
  "RecurringLinkCreated",
  "RecurringLinkUpdated",
] as const;

/**
 * Allowlist for `top_tag` labels on abuse-signal high-score metrics.
 * Free-form tags from user input are collapsed to "other".
 */
export const ALLOWED_ABUSE_TAGS = [
  "spam",
  "scraping",
  "brute_force",
  "invalid_signature",
  "rate_exceeded",
  "unknown",
] as const;

/**
 * Allowlist for `action_type` labels on abuse-signal counters.
 */
export const ALLOWED_ABUSE_ACTION_TYPES = [
  "payment",
  "link_creation",
  "username_claim",
  "webhook_delivery",
  "export_request",
  "login_attempt",
] as const;

/**
 * Allowlist for `service` labels on external-call duration and error counters.
 */
export const ALLOWED_SERVICES = [
  "supabase",
  "sendgrid",
  "soroban_rpc",
  "stellar_horizon",
  "telegram",
  "s3",
] as const;
