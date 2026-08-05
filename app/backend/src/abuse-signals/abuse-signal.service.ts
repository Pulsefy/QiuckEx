import { Injectable, Logger } from "@nestjs/common";
import { createHash } from "node:crypto";
import { SupabaseService } from "../supabase/supabase.service";
import { AppConfigService } from "../config";
import { MetricsService } from "../metrics/metrics.service";
import {
  AbuseSignalRecord,
  AbuseScoreSummary,
  AbuseSignalAggregation,
  SignalPayload,
  SignalOutcome,
  SignalTag,
  SCORE_WEIGHTS,
} from "./abuse-signal.types";

interface RecentSignalContext {
  recentSignals: AbuseSignalRecord[];
  sameIpCount: number;
  invalidCount: number;
  notFoundCount: number;
  rateLimitedCount: number;
  rapidFireCount: number;
  distinctUsernames: number;
  lastOutcomes: SignalOutcome[];
}

@Injectable()
export class AbuseSignalService {
  private readonly logger = new Logger(AbuseSignalService.name);
  private readonly retentionDays: number;
  private readonly scoreThreshold: number;
  private readonly geoEnabled: boolean;
  private readonly salt: string;
  private readonly knownSafeUaFamilies = new Set([
    "Chrome",
    "Firefox",
    "Safari",
    "Edge",
    "Opera",
    "Brave",
  ]);

  constructor(
    private readonly supabaseService: SupabaseService,
    private readonly configService: AppConfigService,
    private readonly metricsService: MetricsService,
  ) {
    this.retentionDays =
      this.configService.abuseSignalRetentionDays;
    this.scoreThreshold =
      this.configService.abuseSignalScoreThreshold;
    this.geoEnabled =
      this.configService.abuseSignalGeoEnabled;
    this.salt =
      this.configService.abuseSignalHashSalt;

    this.logger.log(
      `AbuseSignalService initialized (retention=${this.retentionDays}d, threshold=${this.scoreThreshold})`,
    );
  }

  private hash(value: string): string {
    return createHash("sha256")
      .update(value + this.salt)
      .digest("hex");
  }

  private ipPrefix(ip: string): string | null {
    if (!ip) return null;
    if (ip.includes(":")) return null;
    const parts = ip.split(".");
    if (parts.length !== 4) return null;
    return `${parts[0]}.${parts[1]}.${parts[2]}.0`;
  }

  private parseUaFamily(ua: string): string | null {
    if (!ua || ua.length === 0) return null;
    const browsers = [
      { re: /Edge\/(\S+)/i, name: "Edge" },
      { re: /OPR\/(\S+)/i, name: "Opera" },
      { re: /Brave\/(\S+)/i, name: "Brave" },
      { re: /Chrome\/(\S+)/i, name: "Chrome" },
      { re: /Firefox\/(\S+)/i, name: "Firefox" },
      { re: /Version\/(\S+).*Safari/i, name: "Safari" },
    ];
    for (const { re, name } of browsers) {
      const m = ua.match(re);
      if (m) return `${name}/${m[1]}`;
    }
    if (ua.length > 60) return ua.substring(0, 60);
    return ua;
  }

  private isUaSuspicious(uaFamily: string | null): boolean {
    if (!uaFamily) return true;
    const base = uaFamily.split("/")[0];
    return !this.knownSafeUaFamilies.has(base);
  }

  private async fetchRecentContext(
    ipHash: string,
    uaHash: string,
    windowMs = 60000,
  ): Promise<RecentSignalContext> {
    const since = new Date(Date.now() - windowMs).toISOString();
    const client = this.supabaseService.getClient();

    const { data, error } = await client
      .from("abuse_signals")
      .select("*")
      .eq("ip_address_hash", ipHash)
      .eq("user_agent_hash", uaHash)
      .gte("created_at", since)
      .order("created_at", { ascending: false })
      .limit(100);

    if (error) {
      this.logger.warn(`Failed to fetch recent signals: ${error.message}`);
      return {
        recentSignals: [],
        sameIpCount: 0,
        invalidCount: 0,
        notFoundCount: 0,
        rateLimitedCount: 0,
        rapidFireCount: 0,
        distinctUsernames: 0,
        lastOutcomes: [],
      };
    }

    const signals = (data ?? []) as AbuseSignalRecord[];
    const outcomes = signals.map((s) => s.action_outcome as SignalOutcome);
    const usernames = new Set(
      signals.map((s) => s.target_username).filter(Boolean),
    );

    let rapidFireCount = 0;
    for (let i = 1; i < signals.length; i++) {
      const diff =
        new Date(signals[i - 1].created_at).getTime() -
        new Date(signals[i].created_at).getTime();
      if (diff < 10000) rapidFireCount++;
    }

    return {
      recentSignals: signals,
      sameIpCount: signals.length,
      invalidCount: signals.filter((s) => s.action_outcome !== "success").length,
      notFoundCount: signals.filter((s) => s.action_outcome === "not_found").length,
      rateLimitedCount: signals.filter(
        (s) => s.action_outcome === "rate_limited",
      ).length,
      rapidFireCount,
      distinctUsernames: usernames.size,
      lastOutcomes: outcomes,
    };
  }

  computeAbuseScore(
    outcome: SignalOutcome,
    ctx: RecentSignalContext,
    uaFamily: string | null,
  ): { score: number; tags: SignalTag[] } {
    let score = 0;
    const tags: SignalTag[] = [];

    if (outcome === "invalid_params") score += SCORE_WEIGHTS.invalid_outcome;
    if (outcome === "not_found") {
      score += SCORE_WEIGHTS.not_found;
      if (!tags.includes("brute_force")) tags.push("brute_force");
    }
    if (outcome === "rate_limited") {
      score += SCORE_WEIGHTS.rate_limited;
      if (!tags.includes("scraping")) tags.push("scraping");
    }

    if (ctx.invalidCount >= 3) {
      score += SCORE_WEIGHTS.repeated_invalid * Math.min(ctx.invalidCount, 5);
    }

    if (ctx.rateLimitedCount >= 2) {
      score += SCORE_WEIGHTS.rate_limited;
      if (!tags.includes("scraping")) tags.push("scraping");
    }

    if (ctx.rapidFireCount >= 3) {
      score += SCORE_WEIGHTS.rapid_fire_per_10s * Math.min(ctx.rapidFireCount, 5);
      if (!tags.includes("rapid_fire")) tags.push("rapid_fire");
    }

    if (this.isUaSuspicious(uaFamily)) {
      score += SCORE_WEIGHTS.unknown_ua;
      if (!tags.includes("unknown_ua")) tags.push("unknown_ua");
    }

    if (ctx.notFoundCount >= 5) {
      score += SCORE_WEIGHTS.brute_force_pattern;
      if (!tags.includes("brute_force")) tags.push("brute_force");
    }

    if (ctx.sameIpCount >= 20) {
      score += SCORE_WEIGHTS.scraping_pattern;
      if (!tags.includes("scraping")) tags.push("scraping");
    }

    const finalScore = Math.min(Math.round(score), SCORE_WEIGHTS.max_score);
    return { score: finalScore, tags };
  }

  async recordSignal(payload: SignalPayload): Promise<AbuseSignalRecord | null> {
    const ipHash = this.hash(payload.ipAddress);
    const uaHash = this.hash(payload.userAgent);
    const uaFamily = this.parseUaFamily(payload.userAgent);

    const ctx = await this.fetchRecentContext(ipHash, uaHash);
    const { score, tags } = this.computeAbuseScore(
      payload.actionOutcome,
      ctx,
      uaFamily,
    );

    const retentionUntil = new Date(
      Date.now() + this.retentionDays * 86400000,
    ).toISOString();

    const client = this.supabaseService.getClient();
    const { data, error } = await client
      .from("abuse_signals")
      .insert({
        ip_address_hash: ipHash,
        ip_address_prefix: this.ipPrefix(payload.ipAddress),
        user_agent_hash: uaHash,
        ua_family: uaFamily,
        action_type: payload.actionType,
        action_outcome: payload.actionOutcome,
        target_username: payload.targetUsername ?? null,
        invalid_count:
          payload.actionOutcome !== "success"
            ? ctx.invalidCount + 1
            : ctx.invalidCount,
        abuse_score: score,
        signal_tags: tags,
        request_method: payload.requestMethod ?? null,
        request_path: payload.requestPath ?? null,
        status_code: payload.statusCode ?? null,
        retention_until: retentionUntil,
      })
      .select()
      .single();

    if (error) {
      this.logger.warn(`Failed to record abuse signal: ${error.message}`);
      return null;
    }

    this.metricsService.recordAbuseSignal(
      payload.actionType,
      payload.actionOutcome,
      score,
      tags,
    );

    if (score >= this.scoreThreshold) {
      this.logger.warn(
        `High abuse score [${score}] from IP hash ${ipHash.substring(0, 12)} ` +
          `(UA: ${uaFamily ?? "unknown"}, tags: ${tags.join(", ")})`,
      );
    }

    return data as AbuseSignalRecord;
  }

  async getHighScoreSignals(
    minScore = 20,
    limit = 50,
  ): Promise<AbuseSignalRecord[]> {
    const client = this.supabaseService.getClient();
    const { data, error } = await client
      .from("abuse_signals")
      .select("*")
      .gte("abuse_score", minScore)
      .order("abuse_score", { ascending: false })
      .limit(limit);

    if (error) {
      this.logger.warn(`Failed to fetch high-score signals: ${error.message}`);
      return [];
    }
    return (data ?? []) as AbuseSignalRecord[];
  }

  async getSignalsByIpHash(
    ipHash: string,
    limit = 50,
  ): Promise<AbuseSignalRecord[]> {
    const client = this.supabaseService.getClient();
    const { data, error } = await client
      .from("abuse_signals")
      .select("*")
      .eq("ip_address_hash", ipHash)
      .order("created_at", { ascending: false })
      .limit(limit);

    if (error) {
      this.logger.warn(`Failed to fetch signals by IP: ${error.message}`);
      return [];
    }
    return (data ?? []) as AbuseSignalRecord[];
  }

  async getAggregation(sinceMinutes = 60): Promise<AbuseSignalAggregation> {
    const since = new Date(
      Date.now() - sinceMinutes * 60000,
    ).toISOString();
    const client = this.supabaseService.getClient();

    const { data: signals, error } = await client
      .from("abuse_signals")
      .select("*")
      .gte("created_at", since);

    if (error) {
      this.logger.warn(`Failed to aggregate signals: ${error.message}`);
      return {
        total_signals: 0,
        total_invalid: 0,
        high_score_count: 0,
        distinct_ips: 0,
        top_tags: [],
        top_targets: [],
        outcomes: [],
        since,
      };
    }

    const rows = (signals ?? []) as AbuseSignalRecord[];
    const totalSignals = rows.length;
    const totalInvalid = rows.filter(
      (s) => s.action_outcome !== "success",
    ).length;
    const highScore = rows.filter((s) => s.abuse_score >= this.scoreThreshold).length;
    const distinctIps = new Set(rows.map((s) => s.ip_address_hash)).size;

    const tagCounts = new Map<string, number>();
    const targetCounts = new Map<string, number>();
    const outcomeCounts = new Map<string, number>();

    for (const s of rows) {
      for (const tag of s.signal_tags ?? []) {
        tagCounts.set(tag, (tagCounts.get(tag) ?? 0) + 1);
      }
      if (s.target_username) {
        targetCounts.set(
          s.target_username,
          (targetCounts.get(s.target_username) ?? 0) + 1,
        );
      }
      outcomeCounts.set(
        s.action_outcome,
        (outcomeCounts.get(s.action_outcome) ?? 0) + 1,
      );
    }

    return {
      total_signals: totalSignals,
      total_invalid: totalInvalid,
      high_score_count: highScore,
      distinct_ips: distinctIps,
      top_tags: [...tagCounts.entries()]
        .sort((a, b) => b[1] - a[1])
        .slice(0, 10)
        .map(([tag, count]) => ({ tag, count })),
      top_targets: [...targetCounts.entries()]
        .sort((a, b) => b[1] - a[1])
        .slice(0, 10)
        .map(([username, count]) => ({ username, count })),
      outcomes: [...outcomeCounts.entries()].map(([outcome, count]) => ({
        outcome,
        count,
      })),
      since,
    };
  }

  async getIpSummaries(
    minScore = 20,
    limit = 20,
  ): Promise<AbuseScoreSummary[]> {
    const client = this.supabaseService.getClient();
    const { data, error } = await client
      .from("abuse_signals")
      .select("*")
      .gte("abuse_score", minScore)
      .order("created_at", { ascending: false })
      .limit(500);

    if (error) {
      this.logger.warn(`Failed to fetch IP summaries: ${error.message}`);
      return [];
    }

    const rows = (data ?? []) as AbuseSignalRecord[];
    const byIp = new Map<
      string,
      {
        signals: AbuseSignalRecord[];
        topTags: Map<string, number>;
        usernames: Set<string>;
      }
    >();

    for (const s of rows) {
      if (!byIp.has(s.ip_address_hash)) {
        byIp.set(s.ip_address_hash, {
          signals: [],
          topTags: new Map(),
          usernames: new Set(),
        });
      }
      const entry = byIp.get(s.ip_address_hash)!;
      entry.signals.push(s);
      for (const tag of s.signal_tags ?? []) {
        entry.topTags.set(tag, (entry.topTags.get(tag) ?? 0) + 1);
      }
      if (s.target_username) entry.usernames.add(s.target_username);
    }

    return [...byIp.entries()]
      .map(([hash, entry]) => {
        const last = entry.signals[0];
        const totalInvalid = entry.signals.filter(
          (s) => s.action_outcome !== "success",
        ).length;
        const avgScore =
          entry.signals.reduce((sum, s) => sum + s.abuse_score, 0) /
          entry.signals.length;
        return {
          ip_address_hash: hash,
          ip_address_prefix: last.ip_address_prefix,
          ua_family: last.ua_family,
          geo_country: last.geo_country,
          signal_count: entry.signals.length,
          invalid_count: totalInvalid,
          abuse_score: Math.round(avgScore),
          top_tags: [...entry.topTags.entries()]
            .sort((a, b) => b[1] - a[1])
            .slice(0, 5)
            .map(([t]) => t),
          last_seen: last.created_at,
          target_usernames: [...entry.usernames].slice(0, 10),
        };
      })
      .sort((a, b) => b.abuse_score - a.abuse_score)
      .slice(0, limit);
  }

  async pruneExpiredSignals(): Promise<number> {
    const client = this.supabaseService.getClient();
    const { data, error } = await client
      .from("abuse_signals")
      .delete()
      .lt("retention_until", new Date().toISOString())
      .select("id");

    if (error) {
      this.logger.warn(`Failed to prune expired signals: ${error.message}`);
      return 0;
    }

    const count = (data ?? []).length;
    if (count > 0) {
      this.logger.log(`Pruned ${count} expired abuse signals`);
    }
    return count;
  }
}
