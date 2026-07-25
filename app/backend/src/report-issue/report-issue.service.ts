import { Injectable, Logger, BadRequestException } from '@nestjs/common';
import { createHash } from 'crypto';
import { RedactionService } from '../crash-reporting/redaction.service';
import { ReportIssueRepository } from './report-issue.repository';
import { ReportIssue, ReportIssueSubmission } from './types';
import { AppConfigService } from '../config';

/**
 * Service for handling issue report submissions with redaction and abuse prevention
 */
@Injectable()
export class ReportIssueService {
  private readonly logger = new Logger(ReportIssueService.name);
  private readonly maxReportsPerHour: number;
  private readonly maxReportsPerDay: number;

  constructor(
    private readonly redactionService: RedactionService,
    private readonly repository: ReportIssueRepository,
    private readonly configService: AppConfigService,
  ) {
    this.maxReportsPerHour = this.configService.reportIssueMaxPerHour || 5;
    this.maxReportsPerDay = this.configService.reportIssueMaxPerDay || 20;
  }

  /**
   * Submit a new issue report with redaction and abuse prevention
   * @param submission - The issue report submission
   * @param ipAddress - The submitter's IP address (for abuse detection)
   * @returns The created report ID
   */
  async submitReport(
    submission: ReportIssueSubmission,
    ipAddress: string,
  ): Promise<string> {
    try {
      // Check abuse limits
      await this.checkAbuseLimits(ipAddress);

      // Redact sensitive data from context
      const redactedContext = submission.context
        ? this.redactionService.redactObject(submission.context)
        : undefined;

      // Redact reproduction steps
      const redactedReproduction = submission.reproduction
        ? this.redactionService.redact(submission.reproduction)
        : undefined;

      // Redact description
      const redactedDescription = this.redactionService.redact(submission.description);

      // Create redacted payload for storage
      const redactedPayload: Record<string, unknown> = {
        issueType: submission.issueType,
        title: this.redactionService.redact(submission.title),
        description: redactedDescription,
        environment: submission.environment,
        reproduction: redactedReproduction,
        context: redactedContext,
        attachments: submission.attachments,
      };

      // Create the report
      const report: Omit<ReportIssue, 'id' | 'createdAt'> = {
        userId: submission.userId,
        issueType: submission.issueType,
        title: this.redactionService.redact(submission.title),
        description: redactedDescription,
        environment: submission.environment,
        reproduction: redactedReproduction,
        context: redactedContext as Record<string, unknown> | undefined,
        attachments: submission.attachments,
        redactedPayload,
        ipAddressHash: this.hashIpAddress(ipAddress),
      };

      const reportId = await this.repository.createReportIssue(report);
      
      this.logger.log(`Issue report submitted: ${reportId} (type: ${submission.issueType})`);
      
      return reportId;
    } catch (error) {
      if (error instanceof BadRequestException) {
        throw error;
      }
      this.logger.error('Failed to submit issue report', error);
      throw new Error('Failed to submit issue report');
    }
  }

  /**
   * Get issue reports for a specific user
   * @param userId - The user ID
   * @param limit - Maximum number of reports to return
   * @returns Array of issue reports
   */
  async getReportsByUser(userId: string, limit = 10): Promise<ReportIssue[]> {
    return this.repository.getReportsByUser(userId, limit);
  }

  /**
   * Get all issue reports (admin only)
   * @param limit - Maximum number of reports to return
   * @param offset - Offset for pagination
   * @returns Array of issue reports
   */
  async getAllReports(limit = 50, offset = 0): Promise<ReportIssue[]> {
    return this.repository.getAllReports(limit, offset);
  }

  /**
   * Get a specific issue report by ID
   * @param reportId - The report ID
   * @returns The issue report or null if not found
   */
  async getReportById(reportId: string): Promise<ReportIssue | null> {
    return this.repository.getReportById(reportId);
  }

  /**
   * Check abuse limits for a given IP address
   * @param ipAddress - The IP address to check
   * @throws BadRequestException if limits are exceeded
   */
  private async checkAbuseLimits(ipAddress: string): Promise<void> {
    // Hash the IP address for privacy
    const ipHash = this.hashIpAddress(ipAddress);

    // Check hourly limit
    const hourlyCount = await this.repository.getRecentReportCount(ipHash, 60);
    if (hourlyCount >= this.maxReportsPerHour) {
      this.logger.warn(`Hourly report limit exceeded for IP hash ${ipHash.substring(0, 12)}`);
      throw new BadRequestException(
        `Too many reports submitted. Please try again later.`,
      );
    }

    // Check daily limit
    const dailyCount = await this.repository.getRecentReportCount(ipHash, 1440);
    if (dailyCount >= this.maxReportsPerDay) {
      this.logger.warn(`Daily report limit exceeded for IP hash ${ipHash.substring(0, 12)}`);
      throw new BadRequestException(
        `Daily report limit exceeded. Please try again tomorrow.`,
      );
    }
  }

  /**
   * Hash IP address for privacy
   * @param ipAddress - The IP address to hash
   * @returns Hashed IP address
   */
  private hashIpAddress(ipAddress: string): string {
    const salt = this.configService.reportIssueHashSalt || 'default-salt';
    return createHash('sha256')
      .update(ipAddress + salt)
      .digest('hex');
  }

  /**
   * Delete old issue reports (for cleanup/maintenance)
   * @param olderThanDays - Delete reports older than this many days
   * @returns Number of deleted reports
   */
  async deleteOldReports(olderThanDays: number): Promise<number> {
    return this.repository.deleteOldReports(olderThanDays);
  }
}
