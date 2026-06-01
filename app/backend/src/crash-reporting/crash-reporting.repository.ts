import { Injectable, Logger } from '@nestjs/common';
import { SupabaseService } from '../supabase/supabase.service';
import { CrashReport, CrashReportingSettings } from './types';

/**
 * Repository for crash reporting data persistence
 */
@Injectable()
export class CrashReportingRepository {
  private readonly logger = new Logger(CrashReportingRepository.name);

  constructor(private readonly supabase: SupabaseService) {}

  /**
   * Create a new crash report
   * @param report - The crash report data (without id and createdAt)
   * @returns The created crash report ID
   */
  async createCrashReport(
    report: Omit<CrashReport, 'id' | 'createdAt'>,
  ): Promise<string> {
    const { data, error } = await this.supabase.getClient()
      .from('crash_reports')
      .insert({
        user_id: report.userId,
        error: report.error,
        context: report.context,
        log_lines: report.logLines,
        timestamp: report.timestamp.toISOString(),
      })
      .select('id')
      .single();

    if (error) {
      this.logger.error('Failed to create crash report', error);
      throw new Error(`Failed to create crash report: ${error.message}`);
    }

    return data.id;
  }

  /**
   * Get crash reports for a specific user
   * @param userId - The user ID
   * @param limit - Maximum number of reports to return
   * @returns Array of crash reports
   */
  async getCrashReportsByUser(
    userId: string,
    limit = 10,
  ): Promise<CrashReport[]> {
    const { data, error } = await this.supabase.getClient()
      .from('crash_reports')
      .select('*')
      .eq('user_id', userId)
      .order('timestamp', { ascending: false })
      .limit(limit);

    if (error) {
      this.logger.error(`Failed to get crash reports for user ${userId}`, error);
      throw new Error(`Failed to get crash reports: ${error.message}`);
    }

    return (data || []).map(row => ({
      id: row.id,
      userId: row.user_id,
      error: row.error,
      context: row.context,
      logLines: row.log_lines,
      timestamp: new Date(row.timestamp),
      createdAt: new Date(row.created_at),
    }));
  }

  /**
   * Get user's crash reporting settings
   * @param userId - The user ID
   * @returns The user's settings or null if not found
   */
  async getUserSettings(userId: string): Promise<CrashReportingSettings | null> {
    const { data, error } = await this.supabase.getClient()
      .from('crash_reporting_settings')
      .select('*')
      .eq('user_id', userId)
      .single();

    if (error) {
      // Not found is expected for users who haven't set preferences
      if (error.code === 'PGRST116') {
        return null;
      }
      this.logger.error(`Failed to get settings for user ${userId}`, error);
      throw new Error(`Failed to get user settings: ${error.message}`);
    }

    return {
      userId: data.user_id,
      crashReportingEnabled: data.crash_reporting_enabled,
      updatedAt: new Date(data.updated_at),
    };
  }

  /**
   * Update user's crash reporting settings
   * @param userId - The user ID
   * @param enabled - Whether crash reporting is enabled
   */
  async updateUserSettings(userId: string, enabled: boolean): Promise<void> {
    const { error } = await this.supabase.getClient()
      .from('crash_reporting_settings')
      .upsert({
        user_id: userId,
        crash_reporting_enabled: enabled,
        updated_at: new Date().toISOString(),
      });

    if (error) {
      this.logger.error(`Failed to update settings for user ${userId}`, error);
      throw new Error(`Failed to update user settings: ${error.message}`);
    }
  }

  /**
   * Delete old crash reports (for cleanup/maintenance)
   * @param olderThanDays - Delete reports older than this many days
   * @returns Number of deleted reports
   */
  async deleteOldReports(olderThanDays: number): Promise<number> {
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - olderThanDays);

    const { data, error } = await this.supabase.getClient()
      .from('crash_reports')
      .delete()
      .lt('timestamp', cutoffDate.toISOString())
      .select('id');

    if (error) {
      this.logger.error('Failed to delete old crash reports', error);
      throw new Error(`Failed to delete old reports: ${error.message}`);
    }

    return data?.length || 0;
  }
}
