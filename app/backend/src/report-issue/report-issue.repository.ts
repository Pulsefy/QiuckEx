import { Injectable, Logger } from '@nestjs/common';
import { SupabaseService } from '../supabase/supabase.service';
import { ReportIssue } from './types';

/**
 * Repository for report issue data persistence
 */
@Injectable()
export class ReportIssueRepository {
  private readonly logger = new Logger(ReportIssueRepository.name);

  constructor(private readonly supabase: SupabaseService) {}

  /**
   * Create a new issue report
   * @param report - The issue report data (without id and createdAt)
   * @returns The created issue report ID
   */
  async createReportIssue(
    report: Omit<ReportIssue, 'id' | 'createdAt'>,
  ): Promise<string> {
    const { data, error } = await this.supabase.getClient()
      .from('report_issues')
      .insert({
        user_id: report.userId,
        issue_type: report.issueType,
        title: report.title,
        description: report.description,
        environment: report.environment,
        reproduction: report.reproduction,
        context: report.context,
        attachments: report.attachments,
        redacted_payload: report.redactedPayload,
        ip_address_hash: report.ipAddressHash,
      })
      .select('id')
      .single();

    if (error) {
      this.logger.error('Failed to create issue report', error);
      throw new Error(`Failed to create issue report: ${error.message}`);
    }

    return data.id;
  }

  /**
   * Get issue reports for a specific user
   * @param userId - The user ID
   * @param limit - Maximum number of reports to return
   * @returns Array of issue reports
   */
  async getReportsByUser(
    userId: string,
    limit = 10,
  ): Promise<ReportIssue[]> {
    const { data, error } = await this.supabase.getClient()
      .from('report_issues')
      .select('*')
      .eq('user_id', userId)
      .order('created_at', { ascending: false })
      .limit(limit);

    if (error) {
      this.logger.error(`Failed to get reports for user ${userId}`, error);
      throw new Error(`Failed to get reports: ${error.message}`);
    }

    return (data || []).map(row => this.mapRowToReportIssue(row));
  }

  /**
   * Get all issue reports (admin only)
   * @param limit - Maximum number of reports to return
   * @param offset - Offset for pagination
   * @returns Array of issue reports
   */
  async getAllReports(limit = 50, offset = 0): Promise<ReportIssue[]> {
    const { data, error } = await this.supabase.getClient()
      .from('report_issues')
      .select('*')
      .order('created_at', { ascending: false })
      .range(offset, offset + limit - 1);

    if (error) {
      this.logger.error('Failed to get all reports', error);
      throw new Error(`Failed to get all reports: ${error.message}`);
    }

    return (data || []).map(row => this.mapRowToReportIssue(row));
  }

  /**
   * Get a specific issue report by ID
   * @param reportId - The report ID
   * @returns The issue report or null if not found
   */
  async getReportById(reportId: string): Promise<ReportIssue | null> {
    const { data, error } = await this.supabase.getClient()
      .from('report_issues')
      .select('*')
      .eq('id', reportId)
      .single();

    if (error) {
      if (error.code === 'PGRST116') {
        return null;
      }
      this.logger.error(`Failed to get report ${reportId}`, error);
      throw new Error(`Failed to get report: ${error.message}`);
    }

    return this.mapRowToReportIssue(data);
  }

  /**
   * Get recent reports within a time window (for abuse detection)
   * @param ipHash - Hashed IP address
   * @param windowMinutes - Time window in minutes
   * @returns Count of recent reports
   */
  async getRecentReportCount(ipHash: string, windowMinutes = 60): Promise<number> {
    const since = new Date(Date.now() - windowMinutes * 60000).toISOString();
    
    const { data, error } = await this.supabase.getClient()
      .from('report_issues')
      .select('id')
      .eq('ip_address_hash', ipHash)
      .gte('created_at', since);

    if (error) {
      this.logger.error(`Failed to get recent report count for IP ${ipHash}`, error);
      return 0;
    }

    return data?.length || 0;
  }

  /**
   * Delete old issue reports (for cleanup/maintenance)
   * @param olderThanDays - Delete reports older than this many days
   * @returns Number of deleted reports
   */
  async deleteOldReports(olderThanDays: number): Promise<number> {
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - olderThanDays);

    const { data, error } = await this.supabase.getClient()
      .from('report_issues')
      .delete()
      .lt('created_at', cutoffDate.toISOString())
      .select('id');

    if (error) {
      this.logger.error('Failed to delete old reports', error);
      throw new Error(`Failed to delete old reports: ${error.message}`);
    }

    return data?.length || 0;
  }

  /**
   * Map database row to ReportIssue interface
   */
  private mapRowToReportIssue(row: any): ReportIssue {
    return {
      id: row.id,
      userId: row.user_id,
      issueType: row.issue_type,
      title: row.title,
      description: row.description,
      environment: row.environment,
      reproduction: row.reproduction,
      context: row.context,
      attachments: row.attachments,
      redactedPayload: row.redacted_payload,
      ipAddressHash: row.ip_address_hash,
      createdAt: new Date(row.created_at),
    };
  }
}
