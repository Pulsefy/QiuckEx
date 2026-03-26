import { Injectable, Logger } from '@nestjs/common';
import { SupabaseClient } from '@supabase/supabase-js';
import {
  FrequencyType,
  RecurringStatus,
  ExecutionStatus,
} from './dto/recurring-payment.dto';

// Database type mappings
export type DbRecurringPaymentLink = {
  id: string;
  username: string | null;
  destination: string | null;
  amount: number;
  asset: string;
  asset_issuer: string | null;
  frequency: FrequencyType;
  start_date: string;
  end_date: string | null;
  total_periods: number | null;
  executed_count: number;
  next_execution_date: string;
  status: RecurringStatus;
  memo: string | null;
  memo_type: string | null;
  reference_id: string | null;
  privacy_enabled: boolean;
  created_at: string;
  updated_at: string;
};

export type DbRecurringPaymentExecution = {
  id: string;
  recurring_link_id: string;
  period_number: number;
  scheduled_at: string;
  executed_at: string | null;
  amount: number;
  asset: string;
  status: ExecutionStatus;
  transaction_hash: string | null;
  stellar_operation_id: string | null;
  failure_reason: string | null;
  retry_count: number;
  last_retry_at: string | null;
  notification_sent: boolean;
  notification_sent_at: string | null;
  created_at: string;
};

@Injectable()
export class RecurringPaymentsRepository {
  private readonly logger = new Logger(RecurringPaymentsRepository.name);

  constructor(private readonly supabase: SupabaseClient) {}

  // ---------------------------------------------------------------------------
  // Recurring Payment Links CRUD
  // ---------------------------------------------------------------------------

  async createLink(link: {
    username?: string | null;
    destination?: string | null;
    amount: number;
    asset: string;
    assetIssuer?: string | null;
    frequency: FrequencyType;
    startDate?: Date;
    endDate?: Date | null;
    totalPeriods?: number | null;
    memo?: string | null;
    memoType?: string | null;
    referenceId?: string | null;
    privacyEnabled?: boolean;
  }): Promise<DbRecurringPaymentLink> {
    const { data, error } = await this.supabase
      .from('recurring_payment_links')
      .insert({
        username: link.username || null,
        destination: link.destination || null,
        amount: link.amount,
        asset: link.asset,
        asset_issuer: link.assetIssuer || null,
        frequency: link.frequency,
        start_date: link.startDate?.toISOString() || new Date().toISOString(),
        end_date: link.endDate?.toISOString() || null,
        total_periods: link.totalPeriods || null,
        memo: link.memo || null,
        memo_type: link.memoType || 'text',
        reference_id: link.referenceId || null,
        privacy_enabled: link.privacyEnabled || false,
        next_execution_date: (link.startDate || new Date()).toISOString(),
      })
      .select()
      .single();

    if (error) {
      this.logger.error(`Error creating recurring link: ${error.message}`, error.stack);
      throw error;
    }

    return data as DbRecurringPaymentLink;
  }

  async findById(id: string): Promise<DbRecurringPaymentLink | null> {
    const { data, error } = await this.supabase
      .from('recurring_payment_links')
      .select('*')
      .eq('id', id)
      .single();

    if (error && error.code !== 'PGRST116') {
      this.logger.error(`Error finding recurring link: ${error.message}`, error.stack);
      throw error;
    }

    return data as DbRecurringPaymentLink | null;
  }

  async findByUsername(username: string): Promise<DbRecurringPaymentLink[]> {
    const { data, error } = await this.supabase
      .from('recurring_payment_links')
      .select('*')
      .eq('username', username)
      .in('status', ['active', 'paused']);

    if (error) {
      this.logger.error(`Error finding links by username: ${error.message}`, error.stack);
      throw error;
    }

    return data as DbRecurringPaymentLink[];
  }

  async findByDestination(destination: string): Promise<DbRecurringPaymentLink[]> {
    const { data, error } = await this.supabase
      .from('recurring_payment_links')
      .select('*')
      .eq('destination', destination)
      .in('status', ['active', 'paused']);

    if (error) {
      this.logger.error(`Error finding links by destination: ${error.message}`, error.stack);
      throw error;
    }

    return data as DbRecurringPaymentLink[];
  }

  async listLinks(params: {
    status?: RecurringStatus;
    username?: string;
    destination?: string;
    page?: number;
    limit?: number;
  }): Promise<{ data: DbRecurringPaymentLink[]; total: number }> {
    const { status, username, destination, page = 1, limit = 20 } = params;

    let query = this.supabase.from('recurring_payment_links').select('*', { count: 'exact' });

    if (status) {
      query = query.eq('status', status);
    }

    if (username) {
      query = query.eq('username', username);
    }

    if (destination) {
      query = query.eq('destination', destination);
    }

    const offset = (page - 1) * limit;
    query = query.range(offset, offset + limit - 1).order('created_at', { ascending: false });

    const { data, error, count } = await query;

    if (error) {
      this.logger.error(`Error listing recurring links: ${error.message}`, error.stack);
      throw error;
    }

    return {
      data: data as DbRecurringPaymentLink[],
      total: count || 0,
    };
  }

  async updateLink(
    id: string,
    updates: Partial<{
      amount: number;
      frequency: FrequencyType;
      endDate: Date | null;
      totalPeriods: number | null;
      memo: string | null;
      referenceId: string | null;
    }>,
  ): Promise<DbRecurringPaymentLink> {
    const updateData: Record<string, unknown> = {};

    if (updates.amount !== undefined) updateData.amount = updates.amount;
    if (updates.frequency !== undefined) updateData.frequency = updates.frequency;
    if (updates.endDate !== undefined) updateData.end_date = updates.endDate?.toISOString();
    if (updates.totalPeriods !== undefined) updateData.total_periods = updates.totalPeriods;
    if (updates.memo !== undefined) updateData.memo = updates.memo;
    if (updates.referenceId !== undefined) updateData.reference_id = updates.referenceId;

    const { data, error } = await this.supabase
      .from('recurring_payment_links')
      .update(updateData)
      .eq('id', id)
      .select()
      .single();

    if (error) {
      this.logger.error(`Error updating recurring link: ${error.message}`, error.stack);
      throw error;
    }

    return data as DbRecurringPaymentLink;
  }

  async updateStatus(id: string, status: RecurringStatus): Promise<DbRecurringPaymentLink> {
    const { data, error } = await this.supabase
      .from('recurring_payment_links')
      .update({ status })
      .eq('id', id)
      .select()
      .single();

    if (error) {
      this.logger.error(`Error updating link status: ${error.message}`, error.stack);
      throw error;
    }

    return data as DbRecurringPaymentLink;
  }

  async incrementExecutedCount(id: string): Promise<void> {
    // Direct update approach
    const link = await this.findById(id);
    if (!link) {
      throw new Error(`Link not found: ${id}`);
    }

    const nextDate = this.calculateNextExecutionDate(new Date(link.next_execution_date), link.frequency);
    
    const { error } = await this.supabase
      .from('recurring_payment_links')
      .update({
        executed_count: link.executed_count + 1,
        next_execution_date: nextDate.toISOString(),
      })
      .eq('id', id);

    if (error) {
      this.logger.error(`Error incrementing executed count: ${error.message}`, error.stack);
      throw error;
    }
  }

  private calculateNextExecutionDate(currentDate: Date, frequency: string): Date {
    const next = new Date(currentDate);
    
    switch (frequency) {
      case 'daily':
        next.setDate(next.getDate() + 1);
        break;
      case 'weekly':
        next.setDate(next.getDate() + 7);
        break;
      case 'monthly':
        next.setMonth(next.getMonth() + 1);
        break;
      case 'yearly':
        next.setFullYear(next.getFullYear() + 1);
        break;
    }
    
    return next;
  }

  async deleteLink(id: string): Promise<void> {
    const { error } = await this.supabase.from('recurring_payment_links').delete().eq('id', id);

    if (error) {
      this.logger.error(`Error deleting recurring link: ${error.message}`, error.stack);
      throw error;
    }
  }

  // ---------------------------------------------------------------------------
  // Recurring Payment Executions
  // ---------------------------------------------------------------------------

  async createExecution(execution: {
    recurringLinkId: string;
    periodNumber: number;
    scheduledAt: Date;
    amount: number;
    asset: string;
  }): Promise<DbRecurringPaymentExecution> {
    const { data, error } = await this.supabase
      .from('recurring_payment_executions')
      .insert({
        recurring_link_id: execution.recurringLinkId,
        period_number: execution.periodNumber,
        scheduled_at: execution.scheduledAt.toISOString(),
        amount: execution.amount,
        asset: execution.asset,
        status: 'pending',
        retry_count: 0,
      })
      .select()
      .single();

    if (error) {
      this.logger.error(`Error creating execution: ${error.message}`, error.stack);
      throw error;
    }

    return data as DbRecurringPaymentExecution;
  }

  async findPendingExecutions(limit = 100): Promise<DbRecurringPaymentExecution[]> {
    const { data, error } = await this.supabase
      .from('recurring_payment_executions')
      .select('*')
      .eq('status', 'pending')
      .lte('scheduled_at', new Date().toISOString())
      .order('scheduled_at', { ascending: true })
      .limit(limit);

    if (error) {
      this.logger.error(`Error finding pending executions: ${error.message}`, error.stack);
      throw error;
    }

    return data as DbRecurringPaymentExecution[];
  }

  async findExecutionsByLinkId(linkId: string): Promise<DbRecurringPaymentExecution[]> {
    const { data, error } = await this.supabase
      .from('recurring_payment_executions')
      .select('*')
      .eq('recurring_link_id', linkId)
      .order('period_number', { ascending: true });

    if (error) {
      this.logger.error(`Error finding executions: ${error.message}`, error.stack);
      throw error;
    }

    return data as DbRecurringPaymentExecution[];
  }

  async updateExecutionStatus(
    executionId: string,
    status: ExecutionStatus,
    updates?: {
      executedAt?: Date;
      transactionHash?: string | null;
      failureReason?: string | null;
      retryCount?: number;
      lastRetryAt?: Date | null;
    },
  ): Promise<DbRecurringPaymentExecution> {
    const updateData: Record<string, unknown> = {
      status,
      ...(updates?.executedAt && { executed_at: updates.executedAt.toISOString() }),
      ...(updates?.transactionHash !== undefined && { transaction_hash: updates.transactionHash }),
      ...(updates?.failureReason !== undefined && { failure_reason: updates.failureReason }),
      ...(updates?.retryCount !== undefined && { retry_count: updates.retryCount }),
      ...(updates?.lastRetryAt !== undefined && { last_retry_at: updates.lastRetryAt?.toISOString() }),
    };

    const { data, error } = await this.supabase
      .from('recurring_payment_executions')
      .update(updateData)
      .eq('id', executionId)
      .select()
      .single();

    if (error) {
      this.logger.error(`Error updating execution: ${error.message}`, error.stack);
      throw error;
    }

    return data as DbRecurringPaymentExecution;
  }

  async markNotificationSent(executionId: string): Promise<void> {
    const { error } = await this.supabase
      .from('recurring_payment_executions')
      .update({
        notification_sent: true,
        notification_sent_at: new Date().toISOString(),
      })
      .eq('id', executionId);

    if (error) {
      this.logger.error(`Error marking notification sent: ${error.message}`, error.stack);
      throw error;
    }
  }

  // ---------------------------------------------------------------------------
  // Helper methods
  // ---------------------------------------------------------------------------

  async getDueForExecution(): Promise<DbRecurringPaymentLink[]> {
    const { data, error } = await this.supabase.rpc('should_execute_recurring_link');

    if (error) {
      // Fallback: manual query
      const fallbackResult = await this.supabase
        .from('recurring_payment_links')
        .select('*')
        .eq('status', 'active')
        .lte('next_execution_date', new Date().toISOString())
        .or(`total_periods.is.null,executed_count.lt.total_periods`)
        .or(`end_date.is.null,end_date.gt.${new Date().toISOString()}`);

      if (fallbackResult.error) {
        this.logger.error(`Error getting due links: ${fallbackResult.error.message}`, fallbackResult.error.stack);
        throw fallbackResult.error;
      }

      return fallbackResult.data as DbRecurringPaymentLink[];
    }

    return data as DbRecurringPaymentLink[];
  }
}
