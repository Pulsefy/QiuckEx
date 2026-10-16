import { ApiProperty, ApiPropertyOptional } from "@nestjs/swagger";
import { AbuseScoreSummary, AbuseSignalAggregation, AbuseSignalRecord } from "./abuse-signal.types";

export class AbuseSignalRecordDto implements AbuseSignalRecord {
  @ApiProperty({ description: "Signal record ID", example: "550e8400-e29b-41d4-a716-446655440000" })
  id: string;

  @ApiProperty({ description: "IP address SHA-256 hash", example: "a1b2c3..." })
  ip_address_hash: string;

  @ApiPropertyOptional({ description: "IP prefix or null", nullable: true, example: "192.168.0.0/24" })
  ip_address_prefix: string | null;

  @ApiProperty({ description: "User agent hash", example: "e3b0c4..." })
  user_agent_hash: string;

  @ApiPropertyOptional({ description: "User agent family name or null", nullable: true, example: "Chrome" })
  ua_family: string | null;

  @ApiPropertyOptional({ description: "Geographic country or null", nullable: true, example: "US" })
  geo_country: string | null;

  @ApiPropertyOptional({ description: "Geographic region or null", nullable: true, example: "CA" })
  geo_region: string | null;

  @ApiProperty({ description: "Action type", example: "payment_submit" })
  action_type: string;

  @ApiProperty({ description: "Action outcome", example: "rate_limited" })
  action_outcome: string;

  @ApiPropertyOptional({ description: "Target username or null", nullable: true, example: "alice" })
  target_username: string | null;

  @ApiProperty({ description: "Invalid attempt count", example: 3 })
  invalid_count: number;

  @ApiProperty({ description: "Calculated abuse score", example: 45 })
  abuse_score: number;

  @ApiProperty({ description: "Signal tags", type: [String], example: ["rapid_fire", "scraping"] })
  signal_tags: string[];

  @ApiPropertyOptional({ description: "HTTP request method or null", nullable: true, example: "POST" })
  request_method: string | null;

  @ApiPropertyOptional({ description: "HTTP request path or null", nullable: true, example: "/v1/links" })
  request_path: string | null;

  @ApiPropertyOptional({ description: "HTTP status code or null", nullable: true, example: 429 })
  status_code: number | null;

  @ApiProperty({ description: "Creation ISO timestamp", example: "2026-01-01T00:00:00.000Z" })
  created_at: string;

  @ApiProperty({ description: "Retention expiration ISO timestamp", example: "2026-04-01T00:00:00.000Z" })
  retention_until: string;
}

export class ListAbuseSignalsResponseDto {
  @ApiProperty({ type: [AbuseSignalRecordDto], description: "List of abuse signals" })
  signals: AbuseSignalRecordDto[];

  @ApiProperty({ description: "Total count of returned signals", example: 10 })
  count: number;
}

export class TagCountDto {
  @ApiProperty({ description: "Signal tag name", example: "scraping" })
  tag: string;

  @ApiProperty({ description: "Occurrence count", example: 12 })
  count: number;
}

export class TargetCountDto {
  @ApiProperty({ description: "Target username", example: "alice" })
  username: string;

  @ApiProperty({ description: "Occurrence count", example: 5 })
  count: number;
}

export class OutcomeCountDto {
  @ApiProperty({ description: "Outcome name", example: "rate_limited" })
  outcome: string;

  @ApiProperty({ description: "Occurrence count", example: 8 })
  count: number;
}

export class AbuseSignalAggregationDto implements AbuseSignalAggregation {
  @ApiProperty({ description: "Total signals in window", example: 100 })
  total_signals: number;

  @ApiProperty({ description: "Total invalid attempts", example: 25 })
  total_invalid: number;

  @ApiProperty({ description: "Count of high score signals", example: 10 })
  high_score_count: number;

  @ApiProperty({ description: "Distinct IP addresses observed", example: 15 })
  distinct_ips: number;

  @ApiProperty({ type: [TagCountDto], description: "Top observed tags" })
  top_tags: TagCountDto[];

  @ApiProperty({ type: [TargetCountDto], description: "Top target usernames" })
  top_targets: TargetCountDto[];

  @ApiProperty({ type: [OutcomeCountDto], description: "Outcome counts" })
  outcomes: OutcomeCountDto[];

  @ApiProperty({ description: "Window start ISO timestamp", example: "2026-01-01T00:00:00.000Z" })
  since: string;
}

export class AbuseScoreSummaryDto implements AbuseScoreSummary {
  @ApiProperty({ description: "IP address SHA-256 hash", example: "a1b2c3..." })
  ip_address_hash: string;

  @ApiPropertyOptional({ description: "IP prefix or null", nullable: true, example: "192.168.0.0/24" })
  ip_address_prefix: string | null;

  @ApiPropertyOptional({ description: "User agent family name or null", nullable: true, example: "Chrome" })
  ua_family: string | null;

  @ApiPropertyOptional({ description: "Geographic country or null", nullable: true, example: "US" })
  geo_country: string | null;

  @ApiProperty({ description: "Total signal count", example: 20 })
  signal_count: number;

  @ApiProperty({ description: "Invalid count", example: 5 })
  invalid_count: number;

  @ApiProperty({ description: "Average abuse score", example: 45 })
  abuse_score: number;

  @ApiProperty({ description: "Top observed tags", type: [String], example: ["brute_force"] })
  top_tags: string[];

  @ApiProperty({ description: "Last seen ISO timestamp", example: "2026-01-01T00:00:00.000Z" })
  last_seen: string;

  @ApiProperty({ description: "Target usernames", type: [String], example: ["alice"] })
  target_usernames: string[];
}

export class PruneAbuseSignalsResponseDto {
  @ApiProperty({ description: "Number of pruned expired signals", example: 42 })
  pruned: number;
}
