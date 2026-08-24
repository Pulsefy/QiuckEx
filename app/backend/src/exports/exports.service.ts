import {
  Injectable,
  Logger,
  BadRequestException,
  ForbiddenException,
  NotFoundException,
} from '@nestjs/common';
import { Cron, CronExpression } from '@nestjs/schedule';
import * as crypto from 'crypto';
import { SupabaseService } from '../supabase/supabase.service';
import { AppConfigService } from '../config/app-config.service';

@Injectable()
export class ExportsService {
  private readonly logger = new Logger(ExportsService.name);
  private readonly bucketName: string;
  private readonly retentionDays: number;
  private readonly signingSecret: string;
  private readonly linkTtlSeconds: number;

  constructor(
    private readonly supabaseService: SupabaseService,
    private readonly config: AppConfigService,
  ) {
    this.bucketName = this.config.exportBucket;
    this.retentionDays = this.config.exportRetentionDays;
    this.signingSecret = this.config.exportSigningSecret;
    this.linkTtlSeconds = this.config.exportLinkTtlSeconds;
  }

  /**
   * Helper to ensure the storage bucket exists
   */
  private async ensureBucketExists(): Promise<void> {
    try {
      const client = this.supabaseService.getClient();
      const { data, error } = await client.storage.getBucket(this.bucketName);
      if (error || !data) {
        this.logger.log(`Bucket '${this.bucketName}' does not exist, creating it...`);
        const { error: createError } = await client.storage.createBucket(this.bucketName, {
          public: false,
        });
        if (createError) {
          this.logger.error(`Failed to create bucket '${this.bucketName}': ${createError.message}`);
        }
      }
    } catch (err) {
      this.logger.warn(`Error ensuring bucket exists: ${(err as Error).message}`);
    }
  }

  /**
   * Upload export artifact to Supabase Storage
   * Returns the key (path) of the uploaded file
   */
  async uploadExportArtifact(
    userId: string,
    jobId: string,
    content: string,
    format: 'csv' | 'json',
  ): Promise<string> {
    await this.ensureBucketExists();
    
    // Deterministic key scheme: exports/${userId}/${jobId}.${format}
    const key = `exports/${userId}/${jobId}.${format}`;
    const contentType = format === 'json' ? 'application/json' : 'text/csv';

    this.logger.log(`Uploading export artifact to '${this.bucketName}/${key}'`);

    const client = this.supabaseService.getClient();
    const { error } = await client.storage
      .from(this.bucketName)
      .upload(key, Buffer.from(content), {
        contentType,
        upsert: true,
      });

    if (error) {
      this.logger.error(`Failed to upload export artifact: ${error.message}`);
      throw new Error(`Failed to store export artifact: ${error.message}`);
    }

    return key;
  }

  /**
   * Generate a signed download URL for an export artifact
   */
  generateSignedDownloadUrl(
    userId: string,
    jobId: string,
    format: 'csv' | 'json',
  ): string {
    const expiresAt = new Date(Date.now() + this.linkTtlSeconds * 1000).toISOString();
    
    // Compute HMAC signature of userId:jobId:expiresAt
    const message = `${userId}:${jobId}:${expiresAt}`;
    const signature = crypto
      .createHmac('sha256', this.signingSecret)
      .update(message)
      .digest('hex');

    const baseUrl = this.config.apiBaseUrl;
    const url = new URL(`${baseUrl}/exports/download`);
    url.searchParams.set('userId', userId);
    url.searchParams.set('jobId', jobId);
    url.searchParams.set('format', format);
    url.searchParams.set('expiresAt', expiresAt);
    url.searchParams.set('signature', signature);

    return url.toString();
  }

  /**
   * Verify download URL signature/expiration and check requesting principal authorization
   */
  async verifyAndRetrieveArtifact(
    query: {
      userId: string;
      jobId: string;
      format: string;
      expiresAt: string;
      signature: string;
    },
    requestingPrincipal?: string,
  ): Promise<{ data: Buffer; contentType: string }> {
    const { userId, jobId, format, expiresAt, signature } = query;

    // 1. Verify signature
    const message = `${userId}:${jobId}:${expiresAt}`;
    const expectedSignature = crypto
      .createHmac('sha256', this.signingSecret)
      .update(message)
      .digest('hex');

    if (!this.safeCompare(signature, expectedSignature)) {
      this.logger.warn(`Rejecting tampered download URL signature for user ${userId}, jobId ${jobId}`);
      throw new BadRequestException({
        error: 'URL_INVALID',
        message: 'Download URL is invalid or has been tampered with',
      });
    }

    // 2. Verify expiration
    const expiryDate = new Date(expiresAt);
    if (isNaN(expiryDate.getTime()) || expiryDate.getTime() < Date.now()) {
      this.logger.warn(`Rejecting expired download URL for user ${userId}, jobId ${jobId} (expired at ${expiresAt})`);
      throw new BadRequestException({
        error: 'URL_EXPIRED',
        message: 'Download URL has expired',
      });
    }

    // 3. Verify requesting principal scope
    if (requestingPrincipal && requestingPrincipal !== userId) {
      this.logger.warn(`Rejecting unauthorized access to download export for user ${userId} by principal ${requestingPrincipal}`);
      throw new ForbiddenException({
        error: 'UNAUTHORIZED_ACCESS',
        message: 'You are not authorized to download this export',
      });
    }

    // 4. Retrieve artifact from Supabase Storage
    const key = `exports/${userId}/${jobId}.${format}`;
    const client = this.supabaseService.getClient();
    const { data, error } = await client.storage.from(this.bucketName).download(key);

    if (error || !data) {
      this.logger.error(`Export artifact not found in storage: ${key}`);
      throw new NotFoundException({
        error: 'ARTIFACT_NOT_FOUND',
        message: 'Export file not found in storage',
      });
    }

    const contentType = format === 'json' ? 'application/json' : 'text/csv';
    return {
      data: Buffer.from(await data.arrayBuffer()),
      contentType,
    };
  }

  /**
   * Safe comparison helper to prevent timing attacks
   */
  private safeCompare(a: string, b: string): boolean {
    const bufA = Buffer.from(a);
    const bufB = Buffer.from(b);
    if (bufA.length !== bufB.length) {
      return false;
    }
    return crypto.timingSafeEqual(bufA, bufB);
  }

  /**
   * Daily job to clean up export files that exceed the retention period
   */
  @Cron(CronExpression.EVERY_DAY_AT_MIDNIGHT)
  async cleanupExpiredArtifacts(): Promise<void> {
    this.logger.log(`Starting cleanup of expired export artifacts (retention: ${this.retentionDays} days)`);

    try {
      const client = this.supabaseService.getClient();
      
      // List contents of the 'exports' directory to find user subfolders
      const { data: userFolders, error } = await client.storage
        .from(this.bucketName)
        .list('exports');

      if (error) {
        this.logger.error(`Failed to list user folders in 'exports' for cleanup: ${error.message}`);
        return;
      }

      if (!userFolders || userFolders.length === 0) {
        this.logger.log('No user folders found in exports bucket.');
        return;
      }

      const retentionMs = this.retentionDays * 24 * 60 * 60 * 1000;
      const cutoffTime = Date.now() - retentionMs;
      const expiredKeys: string[] = [];

      for (const folder of userFolders) {
        // Skip placeholders if any
        if (!folder.name || folder.name === '.emptyFolderPlaceholder') {
          continue;
        }

        // List files inside exports/userId folder
        const { data: files, error: filesError } = await client.storage
          .from(this.bucketName)
          .list(`exports/${folder.name}`);

        if (filesError) {
          this.logger.warn(`Failed to list files under exports/${folder.name}: ${filesError.message}`);
          continue;
        }

        if (!files) {
          continue;
        }

        for (const file of files) {
          if (!file.name || file.name === '.emptyFolderPlaceholder') {
            continue;
          }

          const fileDate = file.created_at
            ? new Date(file.created_at).getTime()
            : (file.updated_at ? new Date(file.updated_at).getTime() : Date.now());

          if (fileDate < cutoffTime) {
            expiredKeys.push(`exports/${folder.name}/${file.name}`);
          }
        }
      }

      if (expiredKeys.length > 0) {
        this.logger.log(`Deleting ${expiredKeys.length} expired export files from storage: ${JSON.stringify(expiredKeys)}`);
        const { error: removeError } = await client.storage
          .from(this.bucketName)
          .remove(expiredKeys);

        if (removeError) {
          this.logger.error(`Failed to delete expired export files: ${removeError.message}`);
        } else {
          this.logger.log(`Successfully deleted expired export files.`);
        }
      } else {
        this.logger.log('No expired export artifacts detected.');
      }
    } catch (err) {
      this.logger.error(`Error executing export artifacts cleanup: ${(err as Error).message}`);
    }
  }
}
