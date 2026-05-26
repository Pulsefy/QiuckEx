import { Injectable, Logger } from '@nestjs/common';
import { RedactionService } from './redaction.service';
import { CrashReportingRepository } from './crash-reporting.repository';
import { CrashReport, LogExport, CrashReportingSettings } from './types';

/**
 * Service for capturing crash reports and logs with strict redaction.
 * All captured data is redacted to remove secrets, keys, and PII.
 * Feature is opt-in and disabled by default.
 */
@Injectable()
export class CrashReportingService {
  private readonly logger = new Logger(CrashReportingService.name);
  private readonly maxLogLines = 100; // Last N log lines to capture
  private logBuffer: string[] = [];

  constructor(
    private readonly redactionService: RedactionService,
    private readonly repository: CrashReportingRepository,
  ) {}

  /**
   * Capture a log line to the in-memory buffer
   * @param logLine - The log line to capture
   */
  captureLogLine(logLine: string): void {
    // Keep only the last N lines
    if (this.logBuffer.length >= this.maxLogLines) {
      this.logBuffer.shift();
    }
    this.logBuffer.push(logLine);
  }

  /**
   * Capture a crash report with redacted logs
   * @param userId - The user ID (optional)
   * @param error - The error that caused the crash
   * @param context - Additional context about the crash
   * @returns The created crash report ID
   */
  async captureCrash(
    userId: string | undefined,
    error: Error,
    context?: Record<string, unknown>,
  ): Promise<string | null> {
    try {
      // Check if user has opted in (if userId provided)
      if (userId) {
        const settings = await this.repository.getUserSettings(userId);
        if (!settings?.crashReportingEnabled) {
          this.logger.debug(`Crash reporting disabled for user ${userId}`);
          return null;
        }
      }

      // Redact error and context
      const redactedError = this.redactionService.redactError(error);
      const redactedContext = context 
        ? this.redactionService.redactObject(context) 
        : undefined;

      // Redact log lines
      const redactedLogs = this.redactionService.redactLogLines([...this.logBuffer]);

      // Create crash report
      const crashReport: Omit<CrashReport, 'id' | 'createdAt'> = {
        userId,
        error: redactedError,
        context: redactedContext as Record<string, unknown> | undefined,
        logLines: redactedLogs,
        timestamp: new Date(),
      };

      const reportId = await this.repository.createCrashReport(crashReport);
      
      this.logger.log(`Crash report captured: ${reportId}`);
      
      return reportId;
    } catch (err) {
      // Don't let crash reporting itself crash the application
      this.logger.error('Failed to capture crash report', err);
      return null;
    }
  }

  /**
   * Get user's crash reporting settings
   * @param userId - The user ID
   * @returns The user's settings
   */
  async getUserSettings(userId: string): Promise<CrashReportingSettings | null> {
    return this.repository.getUserSettings(userId);
  }

  /**
   * Update user's crash reporting settings
   * @param userId - The user ID
   * @param enabled - Whether crash reporting is enabled
   */
  async updateUserSettings(userId: string, enabled: boolean): Promise<void> {
    await this.repository.updateUserSettings(userId, enabled);
    this.logger.log(`Crash reporting ${enabled ? 'enabled' : 'disabled'} for user ${userId}`);
  }

  /**
   * Export logs for support (only if user has opted in)
   * @param userId - The user ID
   * @returns The log export data
   */
  async exportLogs(userId: string): Promise<LogExport | null> {
    try {
      const settings = await this.repository.getUserSettings(userId);
      
      if (!settings?.crashReportingEnabled) {
        this.logger.warn(`User ${userId} attempted to export logs but has not opted in`);
        return null;
      }

      // Get recent crash reports for this user
      const crashReports = await this.repository.getCrashReportsByUser(userId, 10);

      // Redact current log buffer
      const redactedLogs = this.redactionService.redactLogLines([...this.logBuffer]);

      const logExport: LogExport = {
        userId,
        exportedAt: new Date(),
        currentLogs: redactedLogs,
        crashReports: crashReports.map(report => ({
          id: report.id,
          timestamp: report.timestamp,
          error: report.error,
          context: report.context,
          logLines: report.logLines,
        })),
      };

      this.logger.log(`Logs exported for user ${userId}`);

      return logExport;
    } catch (err) {
      this.logger.error(`Failed to export logs for user ${userId}`, err);
      return null;
    }
  }

  /**
   * Get crash reports for a user
   * @param userId - The user ID
   * @param limit - Maximum number of reports to return
   * @returns Array of crash reports
   */
  async getCrashReports(userId: string, limit = 10): Promise<CrashReport[]> {
    const settings = await this.repository.getUserSettings(userId);
    
    if (!settings?.crashReportingEnabled) {
      return [];
    }

    return this.repository.getCrashReportsByUser(userId, limit);
  }

  /**
   * Clear the log buffer (useful for testing)
   */
  clearLogBuffer(): void {
    this.logBuffer = [];
  }

  /**
   * Get the current log buffer size
   */
  getLogBufferSize(): number {
    return this.logBuffer.length;
  }
}
