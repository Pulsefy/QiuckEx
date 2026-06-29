export const SIGNAL_ACTION_TYPES = [
  "payment_link_status",
  "link_metadata",
  "payment_submit",
] as const;
export type SignalActionType = (typeof SIGNAL_ACTION_TYPES)[number];

export const SIGNAL_OUTCOMES = [
  "success",
  "invalid_params",
  "not_found",
  "rate_limited",
  "error",
] as const;
export type SignalOutcome = (typeof SIGNAL_OUTCOMES)[number];

export const SIGNAL_TAGS = [
  "scraping",
  "brute_force",
  "replay",
  "geo_anomaly",
  "unknown_ua",
  "rapid_fire",
] as const;
export type SignalTag = (typeof SIGNAL_TAGS)[number];

export interface AbuseSignalRecord {
  id: string;
  ip_address_hash: string;
  ip_address_prefix: string | null;
  user_agent_hash: string;
  ua_family: string | null;
  geo_country: string | null;
  geo_region: string | null;
  action_type: string;
  action_outcome: string;
  target_username: string | null;
  invalid_count: number;
  abuse_score: number;
  signal_tags: string[];
  request_method: string | null;
  request_path: string | null;
  status_code: number | null;
  created_at: string;
  retention_until: string;
}

export interface SignalPayload {
  ipAddress: string;
  userAgent: string;
  actionType: SignalActionType;
  actionOutcome: SignalOutcome;
  targetUsername?: string;
  requestMethod?: string;
  requestPath?: string;
  statusCode?: number;
}

export interface AbuseScoreSummary {
  ip_address_hash: string;
  ip_address_prefix: string | null;
  ua_family: string | null;
  geo_country: string | null;
  signal_count: number;
  invalid_count: number;
  abuse_score: number;
  top_tags: string[];
  last_seen: string;
  target_usernames: string[];
}

export interface AbuseSignalAggregation {
  total_signals: number;
  total_invalid: number;
  high_score_count: number;
  distinct_ips: number;
  top_tags: { tag: string; count: number }[];
  top_targets: { username: string; count: number }[];
  outcomes: { outcome: string; count: number }[];
  since: string;
}

export interface SignalEnvironmentConfig {
  retentionDays: number;
  scoreThreshold: number;
  geoEnabled: boolean;
  hashSalt: string;
}

export const DEFAULT_SIGNAL_CONFIG: SignalEnvironmentConfig = {
  retentionDays: 90,
  scoreThreshold: 30,
  geoEnabled: false,
  hashSalt: "default-abuse-salt",
};

export const SCORE_WEIGHTS = {
  invalid_outcome: 15,
  not_found: 25,
  rate_limited: 30,
  repeated_invalid: 10,
  rapid_fire_per_10s: 20,
  unknown_ua: 5,
  geo_anomaly: 15,
  scraping_pattern: 35,
  brute_force_pattern: 40,
  replay_pattern: 25,
  max_score: 100,
};
