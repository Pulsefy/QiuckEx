/**
 * BE-115: Metric label cardinality protection.
 *
 * The Prometheus registry must never be fed unbounded label values (payment
 * ids, usernames, contract ids, RPC endpoint URLs, free-form event names,
 * tags, ...). Every high-cardinality label is routed through
 * `boundedMetricLabel`, which maps any value outside the label's finite
 * allowlist into the explicit overflow bucket `METRIC_LABEL_OVERFLOW`.
 *
 * Registration-time checks (`assertMetricLabelsBounded`) fail fast when a
 * metric is defined with a label that has no bounded policy, so a test can
 * assert that no metric introduces an uncontrolled label source.
 */

export const METRIC_LABEL_OVERFLOW = "overflow";

/**
 * High-cardinality label sources that must be bucketed.
 *
 * - An entry with an EMPTY allowlist means "never allow raw values" — every
 *   value is recorded under `METRIC_LABEL_OVERFLOW` (e.g. contract ids, URLs).
 * - An entry with a non-empty allowlist passes through only the listed values;
 *   anything else falls into the overflow bucket.
 *
 * Labels NOT listed here are considered bounded by construction (HTTP methods,
 * status codes, enum outcomes) and pass through unchanged.
 */
export const METRIC_LABEL_ALLOWLISTS: Record<string, readonly string[]> = {
  // Unbounded sources: never expose the raw value as a label.
  contract_id: [],
  endpoint: [],
  from_endpoint: [],
  to_endpoint: [],
  event_name: [],
  top_tag: [],

  // Semi-bounded sources with a small, explicit allowlist.
  schema_version: ["0", "1", "2", "3", "4"],
  reason: [
    "timeout",
    "connection_error",
    "http_error",
    "rate_limit",
    "max_retries",
    "health_check",
  ],
  group: ["ip", "user", "public", "webhooks", "internal"],
  key_type: ["ip", "user", "api_key", "org"],
};

/**
 * Every label name the metrics module may use. The registration guard requires
 * each label on a metric to be present here — either as a bounded label
 * (bucketed above) or as a by-construction bounded label (HTTP methods, status
 * codes, enum outcomes). A brand-new label source must be added to this list
 * (and, when high-cardinality, to `METRIC_LABEL_ALLOWLISTS`) before a metric
 * can register it.
 */
export const BOUNDED_METRIC_LABELS: readonly string[] = [
  // HTTP request labels (bounded by construction).
  "method",
  "route",
  "status_code",
  "shadow_status",
  // Bucketed high-cardinality labels.
  "contract_id",
  "endpoint",
  "from_endpoint",
  "to_endpoint",
  "event_name",
  "top_tag",
  "schema_version",
  "reason",
  "group",
  "key_type",
  // Enum-ish labels (bounded by construction).
  "event_type",
  "status",
  "service",
  "operation",
  "error_type",
  "action_type",
  "action_outcome",
  "score_range",
  "outcome",
];

/** Returns the value, or the overflow bucket when it is not in the allowlist. */
export function boundedMetricLabel(labelName: string, value: string): string {
  const allowlist = METRIC_LABEL_ALLOWLISTS[labelName];
  if (allowlist === undefined) return value; // bounded by construction — pass through
  if (allowlist.length === 0) return METRIC_LABEL_OVERFLOW;
  return allowlist.includes(value) ? value : METRIC_LABEL_OVERFLOW;
}

/**
 * Throws when a metric tries to register a label that has no bounded policy.
 * Used by registration paths and by the unit test that enforces BE-115.
 */
export function assertMetricLabelsBounded(labelNames: readonly string[]): void {
  const unknown = labelNames.filter(
    (name) => !BOUNDED_METRIC_LABELS.includes(name),
  );
  if (unknown.length > 0) {
    throw new Error(
      `Unbounded metric label source(s): ${unknown.join(", ")}. ` +
        `Add them to BOUNDED_METRIC_LABELS / METRIC_LABEL_ALLOWLISTS in ` +
        `metric-label-guard.ts before registering a metric with these labels (BE-115).`,
    );
  }
}
