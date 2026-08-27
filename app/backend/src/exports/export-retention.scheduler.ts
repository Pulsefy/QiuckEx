/**
 * Export Artifact Retention Scheduler – BE-102
 *
 * Runs a nightly cleanup of expired export artifacts.
 * The schedule can be overridden via the EXPORT_CLEANUP_CRON env var;
 * defaults to 02:30 UTC daily.
 */

import { Injectable, Logger } from '@nestjs/common';
import { Cron } from '@nestjs/schedule';
import { ExportStorageService } from './export-storage.service';

const DEFAULT_CRON = '30 2 * * *'; // 02:30 UTC daily

@Injectable()
export class ExportRetentionScheduler {
  private readonly logger = new Logger(ExportRetentionScheduler.name);

  constructor(private readonly storageService: ExportStorageService) {}

  /**
   * Nightly cleanup of expired artifacts.
   * Runs at 02:30 UTC by default.
   */
  @Cron(process.env['EXPORT_CLEANUP_CRON'] ?? DEFAULT_CRON)
  async handleRetention(): Promise<void> {
    this.logger.log('Running export artifact retention cleanup');
    try {
      const cleaned = await this.storageService.cleanupExpiredArtifacts();
      this.logger.log(`Export retention cleanup complete: ${cleaned} artifact(s) removed`);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      this.logger.error(`Export retention cleanup failed: ${msg}`);
    }
  }
}
