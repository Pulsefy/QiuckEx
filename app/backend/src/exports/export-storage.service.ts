/**
 * Export Storage Service – BE-102
 *
 * Responsibilities:
 *  - Upload generated export artifacts to Supabase Storage under a
 *    deterministic, principal-scoped key.
 *  - Issue short-lived HMAC-SHA256 signed download URLs that are scoped
 *    to a specific (jobId, userId) pair.
 *  - Validate incoming tokens and reject expired or tampered ones with a
 *    stable error code (EXPORT_LINK_INVALID).
 *  - Clean up artifacts whose retention deadline has passed.
 */

import { Injectable, Logger } from '@nestjs/common';
import { createHmac, timingSafeEqual } from 'crypto';
import { AppConfigService } from '../config/app-config.service';
import { SupabaseService } from '../supabase/supabase.service';

// ─── Constants ────────────────────────────────────────────────────────────────

/** Bucket in Supabase Storage.  Create this bucket (private) in your project. */
const STORAGE_BUCKET = 'export-artifacts';

/** Stable error code returned for any invalid / expired download token. */
export const EXPORT_LINK_INVALID = 'EXPORT_LINK_INVALID';

/** Stable error code returned when an artifact is not found. */
export const EXPORT_NOT_FOUND = 'EXPORT_NOT_FOUND';

// ─── Types ────────────────────────────────────────────────────────────────────

export interface UploadArtifactOptions {
  jobId: string;
  userId: string;
  content: string;
  format: 'csv' | 'json';
  exportType: string;
}

export interface UploadArtifactResult {
  /** Deterministic storage key under which the object was stored. */
  storageKey: string;
  /** Size of the uploaded content in bytes. */
  sizeBytes: number;
}

export interface IssueDownloadTokenOptions {
  jobId: string;
  userId: string;
  /** TTL from now, in seconds.  Defaults to config value. */
  ttlSeconds?: number;
}

export interface DownloadTokenPayload {
  /** Opaque token string to embed in the URL. */
  token: string;
  /** Unix timestamp (seconds) when the token expires. */
  expiresAt: number;
}

export interface VerifyTokenOptions {
  jobId: string;
  userId: string;
  token: string;
}

export interface VerifyTokenResult {
  valid: boolean;
  /** Stable error code when valid === false. */
  errorCode?: typeof EXPORT_LINK_INVALID;
}

export interface ArtifactRecord {
  jobId: string;
  userId: string;
  storageKey: string;
  sizeBytes: number;
  mimeType: string;
  expiresAt: Date;
  createdAt: Date;
}

// ─── Service ──────────────────────────────────────────────────────────────────

@Injectable()
export class ExportStorageService {
  private readonly logger = new Logger(ExportStorageService.name);

  constructor(
    private readonly config: AppConfigService,
    private readonly supabase: SupabaseService,
  ) {}

  // ── Public API ─────────────────────────────────────────────────────────────

  /**
   * Upload the export artifact to object storage and persist its metadata.
   *
   * Key scheme: `exports/{userId}/{jobId}.{ext}`
   *   – deterministic and principal-scoped, so the same job never clobbers
   *     another user's artifact even if job IDs were somehow recycled.
   */
  async uploadArtifact(opts: UploadArtifactOptions): Promise<UploadArtifactResult> {
    const { jobId, userId, content, format } = opts;
    const ext = format === 'csv' ? 'csv' : 'json';
    const storageKey = `exports/${userId}/${jobId}.${ext}`;
    const mimeType = format === 'csv' ? 'text/csv' : 'application/json';
    const contentBytes = Buffer.from(content, 'utf8');
    const sizeBytes = contentBytes.length;

    this.logger.log(
      `Uploading export artifact: key=${storageKey}, size=${sizeBytes}B (jobId=${jobId})`,
    );

    const client = this.supabase.getClient();

    const { error: uploadError } = await client.storage
      .from(STORAGE_BUCKET)
      .upload(storageKey, contentBytes, {
        contentType: mimeType,
        upsert: true,
      });

    if (uploadError) {
      throw new Error(
        `Failed to upload export artifact to storage: ${uploadError.message}`,
      );
    }

    // Persist metadata so we can validate ownership on download and run retention
    const ttlHours = this.config.exportArtifactTtlHours;
    const expiresAt = new Date(Date.now() + ttlHours * 60 * 60 * 1000);

    await this.persistArtifactRecord({
      jobId,
      userId,
      storageKey,
      sizeBytes,
      mimeType,
      expiresAt,
    });

    this.logger.log(
      `Artifact uploaded and recorded (jobId=${jobId}, expiresAt=${expiresAt.toISOString()})`,
    );

    return { storageKey, sizeBytes };
  }

  /**
   * Issue a time-limited, principal-scoped download token.
   *
   * Token format (all fields joined by '|', then HMAC-SHA256'd):
   *   `<jobId>|<userId>|<expiresAt>`
   *
   * The token embeds its own expiry so the server stays stateless for
   * validation; the database record is only needed for ownership and retention.
   */
  issueDownloadToken(opts: IssueDownloadTokenOptions): DownloadTokenPayload {
    const { jobId, userId } = opts;
    const ttlSeconds =
      opts.ttlSeconds ?? this.config.exportArtifactTtlHours * 3600;
    const expiresAt = Math.floor(Date.now() / 1000) + ttlSeconds;
    const payload = `${jobId}|${userId}|${expiresAt}`;
    const signature = this.sign(payload);
    // Token = base64url(<payload>) + '.' + base64url(<signature>)
    const token = `${toBase64Url(payload)}.${toBase64Url(signature)}`;
    return { token, expiresAt };
  }

  /**
   * Verify a download token.
   *
   * Returns { valid: false, errorCode: EXPORT_LINK_INVALID } for any of:
   *   - malformed token structure
   *   - tampered payload (HMAC mismatch, timing-safe comparison)
   *   - wrong jobId or userId
   *   - token past its expiry time
   */
  verifyDownloadToken(opts: VerifyTokenOptions): VerifyTokenResult {
    const { jobId, userId, token } = opts;

    const parts = token.split('.');
    if (parts.length !== 2) {
      return { valid: false, errorCode: EXPORT_LINK_INVALID };
    }

    let payload: string;
    let receivedSig: string;
    try {
      payload = fromBase64Url(parts[0]);
      receivedSig = fromBase64Url(parts[1]);
    } catch {
      return { valid: false, errorCode: EXPORT_LINK_INVALID };
    }

    // Constant-time signature comparison
    const expectedSig = this.sign(payload);
    if (!safeEqual(receivedSig, expectedSig)) {
      return { valid: false, errorCode: EXPORT_LINK_INVALID };
    }

    // Validate payload structure
    const segments = payload.split('|');
    if (segments.length !== 3) {
      return { valid: false, errorCode: EXPORT_LINK_INVALID };
    }

    const [tokenJobId, tokenUserId, expiresAtStr] = segments;
    const expiresAt = parseInt(expiresAtStr, 10);

    if (tokenJobId !== jobId || tokenUserId !== userId) {
      return { valid: false, errorCode: EXPORT_LINK_INVALID };
    }

    if (isNaN(expiresAt) || Math.floor(Date.now() / 1000) > expiresAt) {
      return { valid: false, errorCode: EXPORT_LINK_INVALID };
    }

    return { valid: true };
  }

  /**
   * Generate a short-lived Supabase Storage signed URL for direct download.
   * Only called after token ownership has been verified.
   *
   * @param storageKey - The object key in STORAGE_BUCKET.
   * @param ttlSeconds - Lifetime of the returned URL (default: 5 minutes).
   */
  async createPresignedDownloadUrl(
    storageKey: string,
    ttlSeconds = 300,
  ): Promise<string> {
    const client = this.supabase.getClient();
    const { data, error } = await client.storage
      .from(STORAGE_BUCKET)
      .createSignedUrl(storageKey, ttlSeconds);

    if (error || !data?.signedUrl) {
      throw new Error(
        `Failed to create presigned download URL: ${error?.message ?? 'unknown error'}`,
      );
    }

    return data.signedUrl;
  }

  /**
   * Look up the artifact record for a given job.
   * Returns null when no record exists (or it has been deleted).
   */
  async findArtifactRecord(jobId: string): Promise<ArtifactRecord | null> {
    const client = this.supabase.getClient();
    const { data, error } = await client
      .from('export_artifacts')
      .select('*')
      .eq('job_id', jobId)
      .maybeSingle();

    if (error) {
      throw new Error(`Failed to look up artifact record: ${error.message}`);
    }

    if (!data) return null;
    return this.mapRow(data);
  }

  /**
   * Delete artifacts whose `expires_at` is in the past.
   * Removes both the storage object and the metadata row.
   *
   * @returns Number of artifacts cleaned up.
   */
  async cleanupExpiredArtifacts(): Promise<number> {
    const client = this.supabase.getClient();
    const now = new Date().toISOString();

    const { data: expired, error: fetchError } = await client
      .from('export_artifacts')
      .select('job_id, storage_key')
      .lt('expires_at', now);

    if (fetchError) {
      this.logger.error(
        `Failed to fetch expired artifacts: ${fetchError.message}`,
      );
      return 0;
    }

    if (!expired || expired.length === 0) return 0;

    let cleaned = 0;

    for (const row of expired) {
      try {
        // Remove from object storage
        const { error: storageError } = await client.storage
          .from(STORAGE_BUCKET)
          .remove([row.storage_key]);

        if (storageError) {
          this.logger.warn(
            `Could not remove storage object ${row.storage_key}: ${storageError.message}`,
          );
        }

        // Remove metadata row
        const { error: dbError } = await client
          .from('export_artifacts')
          .delete()
          .eq('job_id', row.job_id);

        if (dbError) {
          this.logger.warn(
            `Could not delete artifact record for job ${row.job_id}: ${dbError.message}`,
          );
        } else {
          cleaned++;
        }
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        this.logger.error(
          `Unexpected error cleaning artifact for job ${row.job_id}: ${msg}`,
        );
      }
    }

    if (cleaned > 0) {
      this.logger.log(`Cleaned up ${cleaned} expired export artifact(s)`);
    }

    return cleaned;
  }

  // ── Private helpers ────────────────────────────────────────────────────────

  private async persistArtifactRecord(
    record: Omit<ArtifactRecord, 'createdAt'>,
  ): Promise<void> {
    const client = this.supabase.getClient();
    const { error } = await client.from('export_artifacts').upsert(
      {
        job_id: record.jobId,
        user_id: record.userId,
        storage_key: record.storageKey,
        size_bytes: record.sizeBytes,
        mime_type: record.mimeType,
        expires_at: record.expiresAt.toISOString(),
      },
      { onConflict: 'job_id' },
    );

    if (error) {
      throw new Error(`Failed to persist artifact record: ${error.message}`);
    }
  }

  private sign(payload: string): string {
    return createHmac('sha256', this.config.exportDownloadSecret)
      .update(payload)
      .digest('hex');
  }

  private mapRow(row: Record<string, unknown>): ArtifactRecord {
    return {
      jobId: row['job_id'] as string,
      userId: row['user_id'] as string,
      storageKey: row['storage_key'] as string,
      sizeBytes: row['size_bytes'] as number,
      mimeType: row['mime_type'] as string,
      expiresAt: new Date(row['expires_at'] as string),
      createdAt: new Date(row['created_at'] as string),
    };
  }
}

// ─── Pure utilities (module-private) ─────────────────────────────────────────

function toBase64Url(value: string): string {
  return Buffer.from(value, 'utf8')
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

function fromBase64Url(encoded: string): string {
  const padded =
    encoded.replace(/-/g, '+').replace(/_/g, '/') +
    '='.repeat((4 - (encoded.length % 4)) % 4);
  return Buffer.from(padded, 'base64').toString('utf8');
}

function safeEqual(a: string, b: string): boolean {
  // Ensure both buffers are the same length before comparing so
  // timingSafeEqual doesn't throw.
  const bufA = Buffer.from(a, 'utf8');
  const bufB = Buffer.from(b, 'utf8');
  if (bufA.length !== bufB.length) return false;
  return timingSafeEqual(bufA, bufB);
}
