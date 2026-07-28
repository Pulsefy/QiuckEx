import { Injectable, Logger } from "@nestjs/common";
import { SupabaseService } from "../supabase/supabase.service";

export type JobReplayLogStatus =
  | "queued"
  | "succeeded"
  | "failed"
  | "rejected";

export interface JobReplayLogEntry {
  id: string;
  jobId: string;
  jobType: string;
  status: JobReplayLogStatus;
  reason?: string;
  triggeredBy: string;
  previousAttempts: number;
  createdAt: string;
}

@Injectable()
export class JobReplayRepository {
  private readonly logger = new Logger(JobReplayRepository.name);

  constructor(private readonly supabase: SupabaseService) {}

  async createReplayLog(params: {
    jobId: string;
    jobType: string;
    status: JobReplayLogStatus;
    previousAttempts: number;
    reason?: string;
    triggeredBy?: string;
  }): Promise<JobReplayLogEntry | null> {
    const { data, error } = await this.supabase
      .getClient()
      .from("job_replay_log")
      .insert({
        job_id: params.jobId,
        job_type: params.jobType,
        status: params.status,
        previous_attempts: params.previousAttempts,
        reason: params.reason ?? null,
        triggered_by: params.triggeredBy ?? "api",
      })
      .select(
        "id, job_id, job_type, status, reason, triggered_by, previous_attempts, created_at",
      )
      .single();

    if (error) {
      this.logger.warn(`Failed to persist job replay log: ${error.message}`);
      return null;
    }

    return this.mapRow(data);
  }

  async updateReplayLog(
    id: string,
    updates: {
      status: JobReplayLogStatus;
      reason?: string;
    },
  ): Promise<void> {
    const { error } = await this.supabase
      .getClient()
      .from("job_replay_log")
      .update({
        status: updates.status,
        reason: updates.reason ?? null,
      })
      .eq("id", id);

    if (error) {
      this.logger.warn(`Failed to update job replay log: ${error.message}`);
    }
  }

  async getReplayLogsForJob(jobId: string): Promise<JobReplayLogEntry[]> {
    const { data, error } = await this.supabase
      .getClient()
      .from("job_replay_log")
      .select(
        "id, job_id, job_type, status, reason, triggered_by, previous_attempts, created_at",
      )
      .eq("job_id", jobId)
      .order("created_at", { ascending: false });

    if (error) {
      this.logger.warn(`Failed to list job replay logs: ${error.message}`);
      return [];
    }

    return (data ?? []).map((row) => this.mapRow(row));
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private mapRow(row: any): JobReplayLogEntry {
    return {
      id: row.id,
      jobId: row.job_id,
      jobType: row.job_type,
      status: row.status as JobReplayLogStatus,
      reason: row.reason ?? undefined,
      triggeredBy: row.triggered_by,
      previousAttempts: row.previous_attempts,
      createdAt: row.created_at,
    };
  }
}