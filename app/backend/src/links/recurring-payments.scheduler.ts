import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { Cron, CronExpression } from '@nestjs/schedule';
import { EventEmitter2 } from '@nestjs/event-emitter';
import { RecurringPaymentsService } from './recurring-payments.service';
import { RecurringPaymentsRepository, DbRecurringPaymentLink, DbRecurringPaymentExecution } from './recurring-payments.repository';
import { ExecutionStatus } from './dto/recurring-payment.dto';
import { RecurringPaymentProcessor } from '../stellar/recurring-payment-processor';

@Injectable()
export class RecurringPaymentsScheduler implements OnModuleInit {
  private readonly logger = new Logger(RecurringPaymentsScheduler.name);
  private readonly maxRetries: number;
  private readonly retryBackoffMs: number;
  private readonly notificationHoursBefore: number;

  constructor(
    private readonly schedulerService: RecurringPaymentsService,
    private readonly repository: RecurringPaymentsRepository,
    private readonly paymentProcessor: RecurringPaymentProcessor,
    private readonly eventEmitter: EventEmitter2,
  ) {
    this.maxRetries = parseInt(process.env.RECURRING_PAYMENT_MAX_RETRY || '3');
    this.retryBackoffMs = parseInt(process.env.RECURRING_PAYMENT_RETRY_BACKOFF_MS || '60000');
    this.notificationHoursBefore = parseInt(process.env.RECURRING_PAYMENT_NOTIFICATION_HOURS_BEFORE || '24');
  }

  onModuleInit(): void {
    this.logger.log('Recurring payments scheduler initialized');
    this.logger.log(`Configuration: maxRetries=${this.maxRetries}, retryBackoffMs=${this.retryBackoffMs}ms, notificationHoursBefore=${this.notificationHoursBefore}h`);
  }

  // ---------------------------------------------------------------------------
  // Cron Jobs
  // ---------------------------------------------------------------------------

  /**
   * Check for pending payments every minute
   */
  @Cron(CronExpression.EVERY_MINUTE)
  async checkAndExecutePendingPayments(): Promise<void> {
    try {
      this.logger.debug('Checking for pending recurring payments...');

      const linksDue = await this.schedulerService.getLinksDueForExecution();

      if (linksDue.length === 0) {
        this.logger.debug('No recurring payments due for execution');
        return;
      }

      this.logger.log(`Found ${linksDue.length} recurring payment(s) due for execution`);

      // Process each link sequentially to avoid race conditions
      for (const link of linksDue) {
        await this.processRecurringPayment(link);
      }
    } catch (error: any) {
      this.logger.error(`Error in scheduled payment execution: ${error.message}`, error.stack);
    }
  }

  /**
   * Send payment due notifications 24 hours before scheduled date
   */
  @Cron(CronExpression.EVERY_HOUR)
  async sendUpcomingPaymentNotifications(): Promise<void> {
    try {
      this.logger.debug('Checking for upcoming payment notifications...');

      // This would query for payments scheduled in the next 24 hours
      // Implementation depends on specific notification requirements
      // For now, we'll skip detailed implementation
    } catch (error: any) {
      this.logger.error(`Error sending notifications: ${error.message}`, error.stack);
    }
  }

  // ---------------------------------------------------------------------------
  // Payment Processing Logic
  // ---------------------------------------------------------------------------

  private async processRecurringPayment(link: DbRecurringPaymentLink): Promise<void> {
    const linkId = link.id;

    try {
      this.logger.log(`Processing recurring payment for link: ${linkId}`);

      // Determine the next period number
      const nextPeriodNumber = link.executed_count + 1;

      // Create execution record
      const execution = await this.repository.createExecution({
        recurringLinkId: linkId,
        periodNumber: nextPeriodNumber,
        scheduledAt: new Date(link.next_execution_date),
        amount: link.amount,
        asset: link.asset,
      });

      this.logger.log(`Created execution record: ${execution.id} for period ${nextPeriodNumber}`);

      // Execute the payment
      await this.executeSinglePayment(link, execution);
    } catch (error: any) {
      this.logger.error(`Error processing recurring payment ${linkId}: ${error.message}`, error.stack);

      // Mark as failed
      await this.schedulerService.markPaymentFailure(
        linkId,
        error.message || 'Unknown error',
        0, // Initial attempt
      );
    }
  }

  private async executeSinglePayment(
    link: DbRecurringPaymentLink,
    execution: DbRecurringPaymentExecution,
  ): Promise<void> {
    const executionId = execution.id;

    try {
      this.logger.log(`Executing payment for execution: ${executionId}`);

      // Determine recipient
      const recipientAddress = link.destination || (await this.resolveUsernameToAddress(link.username!));

      if (!recipientAddress) {
        throw new Error('Could not resolve recipient address');
      }

      // Submit payment via Stellar
      const transactionHash = await this.paymentProcessor.submitRecurringPayment({
        recipientAddress,
        amount: link.amount,
        assetCode: link.asset,
        assetIssuer: link.asset_issuer || undefined,
        memo: link.memo || undefined,
        memoType: link.memo_type || 'text',
        referenceId: link.reference_id || undefined,
      });

      this.logger.log(`Payment successful: ${transactionHash}`);

      // Mark as successful
      await this.schedulerService.markPaymentSuccess(executionId, transactionHash);

      // Emit success event
      this.eventEmitter.emit('recurring.payment.executed', {
        executionId,
        linkId: link.id,
        transactionHash,
        periodNumber: execution.period_number,
      });

      // Send notification
      await this.notifyUser(link, execution, 'success', transactionHash);
    } catch (error: any) {
      this.logger.error(`Payment execution failed: ${error.message}`, error.stack);

      const currentRetryCount = execution.retry_count + 1;

      // Mark as failed (with retry logic)
      await this.schedulerService.markPaymentFailure(
        executionId,
        error.message || 'Payment execution failed',
        currentRetryCount,
      );

      // Emit failure event
      this.eventEmitter.emit('recurring.payment.failed', {
        executionId,
        linkId: link.id,
        failureReason: error.message,
        retryCount: currentRetryCount,
        permanent: currentRetryCount >= this.maxRetries,
      });

      // Send failure notification
      await this.notifyUser(link, execution, 'failed', undefined, error.message);

      // Re-throw to let caller handle
      throw error;
    }
  }

  // ---------------------------------------------------------------------------
  // Notification Helpers
  // ---------------------------------------------------------------------------

  private async notifyUser(
    link: DbRecurringPaymentLink,
    execution: DbRecurringPaymentExecution,
    type: 'success' | 'failed' | 'due',
    transactionHash?: string,
    failureReason?: string,
  ): Promise<void> {
    try {
      const eventType =
        type === 'success'
          ? 'recurring.payment.success'
          : type === 'failed'
          ? 'recurring.payment.failed'
          : 'recurring.payment.due';

      this.eventEmitter.emit(eventType, {
        linkId: link.id,
        executionId: execution.id,
        username: link.username,
        destination: link.destination,
        amount: link.amount,
        asset: link.asset,
        periodNumber: execution.period_number,
        transactionHash,
        failureReason,
      });

      this.logger.debug(`Emitted notification event: ${eventType}`);
    } catch (error: any) {
      this.logger.error(`Error emitting notification: ${error.message}`, error.stack);
    }
  }

  private async resolveUsernameToAddress(username: string): Promise<string | null> {
    // TODO: Integrate with usernames module to resolve username to Stellar address
    // For now, return null - in production this would query the usernames table
    this.logger.warn('Username resolution not yet implemented');
    return null;
  }
}
