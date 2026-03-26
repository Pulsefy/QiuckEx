import { Injectable, Logger, NotFoundException, BadRequestException } from '@nestjs/common';
import { EventEmitter2 } from '@nestjs/event-emitter';
import {
  CreateRecurringPaymentLinkDto,
  UpdateRecurringPaymentLinkDto,
  RecurringPaymentLinkResponseDto,
  RecurringPaymentExecutionDto,
  FrequencyType,
  RecurringStatus,
  ExecutionStatus,
} from './dto/recurring-payment.dto';
import { RecurringPaymentsRepository, DbRecurringPaymentLink, DbRecurringPaymentExecution } from './recurring-payments.repository';
import { LinkValidationError, LinkErrorCode } from './errors';

@Injectable()
export class RecurringPaymentsService {
  private readonly logger = new Logger(RecurringPaymentsService.name);

  constructor(
    private readonly repository: RecurringPaymentsRepository,
    private readonly eventEmitter: EventEmitter2,
  ) {}

  // ---------------------------------------------------------------------------
  // Public API Methods
  // ---------------------------------------------------------------------------

  /**
   * Create a new recurring payment link
   */
  async createRecurringLink(
    dto: CreateRecurringPaymentLinkDto,
  ): Promise<RecurringPaymentLinkResponseDto> {
    // Validate input
    this.validateCreateDto(dto);

    try {
      // Calculate initial execution date
      const startDate = dto.startDate ? new Date(dto.startDate) : new Date();
      this.calculateNextExecutionDate(startDate, dto.frequency);

      // Create the link
      const link = await this.repository.createLink({
        username: dto.username || null,
        destination: dto.destination || null,
        amount: dto.amount,
        asset: dto.asset,
        assetIssuer: dto.assetIssuer || null,
        frequency: dto.frequency,
        startDate,
        endDate: dto.endDate ? new Date(dto.endDate) : null,
        totalPeriods: dto.totalPeriods || null,
        memo: dto.memo || null,
        memoType: dto.memoType || 'text',
        referenceId: dto.referenceId || null,
        privacyEnabled: dto.privacyEnabled || false,
      });

      // Create first execution record
      await this.repository.createExecution({
        recurringLinkId: link.id,
        periodNumber: 1,
        scheduledAt: startDate,
        amount: dto.amount,
        asset: dto.asset,
      });

      this.logger.log(`Created recurring payment link: ${link.id}`);

      // Emit event
      this.eventEmitter.emit('recurring.link.created', {
        linkId: link.id,
        username: link.username,
        destination: link.destination,
      });

      return this.mapToResponseDto(link);
    } catch (error: unknown) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      this.logger.error(`Error creating recurring link: ${errorMessage}`, error instanceof Error ? error.stack : undefined);
      throw new BadRequestException(
        `Failed to create recurring payment link: ${errorMessage}`,
      );
    }
  }

  /**
   * Get a recurring payment link by ID
   */
  async getRecurringLinkById(id: string): Promise<RecurringPaymentLinkResponseDto> {
    const link = await this.repository.findById(id);

    if (!link) {
      throw new NotFoundException(`Recurring payment link not found: ${id}`);
    }

    const executions = await this.repository.findExecutionsByLinkId(id);
    return this.mapToResponseDto(link, executions);
  }

  /**
   * List recurring payment links
   */
  async listRecurringLinks(params: {
    status?: RecurringStatus;
    username?: string;
    destination?: string;
    page?: number;
    limit?: number;
  }): Promise<{ data: RecurringPaymentLinkResponseDto[]; total: number }> {
    const result = await this.repository.listLinks(params);

    const data = result.data.map((link) => this.mapToResponseDto(link));

    return {
      data,
      total: result.total,
    };
  }

  /**
   * Update a recurring payment link
   */
  async updateRecurringLink(
    id: string,
    dto: UpdateRecurringPaymentLinkDto,
  ): Promise<RecurringPaymentLinkResponseDto> {
    const existingLink = await this.repository.findById(id);

    if (!existingLink) {
      throw new NotFoundException(`Recurring payment link not found: ${id}`);
    }

    // Validate updates
    this.validateUpdateDto(dto, existingLink);

    try {
      const updatedLink = await this.repository.updateLink(id, {
        amount: dto.amount,
        frequency: dto.frequency,
        endDate: dto.endDate ? new Date(dto.endDate) : undefined,
        totalPeriods: dto.totalPeriods,
        memo: dto.memo,
        referenceId: dto.referenceId,
      });

      this.logger.log(`Updated recurring payment link: ${id}`);

      // Emit event
      this.eventEmitter.emit('recurring.link.updated', {
        linkId: id,
        changes: dto,
      });

      return this.mapToResponseDto(updatedLink);
    } catch (error: unknown) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      this.logger.error(`Error updating recurring link: ${errorMessage}`, error instanceof Error ? error.stack : undefined);
      throw new BadRequestException(
        `Failed to update recurring payment link: ${errorMessage}`,
      );
    }
  }

  /**
   * Cancel a recurring payment link
   */
  async cancelRecurringLink(id: string): Promise<RecurringPaymentLinkResponseDto> {
    const link = await this.repository.findById(id);

    if (!link) {
      throw new NotFoundException(`Recurring payment link not found: ${id}`);
    }

    if (link.status === RecurringStatus.CANCELLED) {
      throw new BadRequestException('Link is already cancelled');
    }

    const updatedLink = await this.repository.updateStatus(id, RecurringStatus.CANCELLED);

    this.logger.log(`Cancelled recurring payment link: ${id}`);

    // Emit event
    this.eventEmitter.emit('recurring.link.cancelled', {
      linkId: id,
      username: link.username,
      destination: link.destination,
    });

    return this.mapToResponseDto(updatedLink);
  }

  /**
   * Pause a recurring payment link
   */
  async pauseRecurringLink(id: string): Promise<RecurringPaymentLinkResponseDto> {
    const link = await this.repository.findById(id);

    if (!link) {
      throw new NotFoundException(`Recurring payment link not found: ${id}`);
    }

    if (link.status !== RecurringStatus.ACTIVE) {
      throw new BadRequestException('Link is not active');
    }

    const updatedLink = await this.repository.updateStatus(id, RecurringStatus.PAUSED);

    this.logger.log(`Paused recurring payment link: ${id}`);

    // Emit event
    this.eventEmitter.emit('recurring.link.paused', {
      linkId: id,
      username: link.username,
      destination: link.destination,
    });

    return this.mapToResponseDto(updatedLink);
  }

  /**
   * Resume a paused recurring payment link
   */
  async resumeRecurringLink(id: string): Promise<RecurringPaymentLinkResponseDto> {
    const link = await this.repository.findById(id);

    if (!link) {
      throw new NotFoundException(`Recurring payment link not found: ${id}`);
    }

    if (link.status !== RecurringStatus.PAUSED) {
      throw new BadRequestException('Link is not paused');
    }

    // Calculate next execution date from now
    this.calculateNextExecutionDate(new Date(), link.frequency);

    await this.repository.updateLink(id, {
      // Reset next execution date
    });

    // Manually update status and next_execution_date
    const statusUpdatedLink = await this.repository.updateStatus(id, RecurringStatus.ACTIVE);

    this.logger.log(`Resumed recurring payment link: ${id}`);

    // Emit event
    this.eventEmitter.emit('recurring.link.resumed', {
      linkId: id,
      username: link.username,
      destination: link.destination,
    });

    return this.mapToResponseDto(statusUpdatedLink);
  }

  /**
   * Get execution history for a recurring link
   */
  async getExecutionHistory(linkId: string): Promise<RecurringPaymentExecutionDto[]> {
    const link = await this.repository.findById(linkId);

    if (!link) {
      throw new NotFoundException(`Recurring payment link not found: ${linkId}`);
    }

    const executions = await this.repository.findExecutionsByLinkId(linkId);
    return executions.map((exec) => this.mapExecutionToDto(exec));
  }

  // ---------------------------------------------------------------------------
  // Scheduler Integration Methods
  // ---------------------------------------------------------------------------

  /**
   * Get all links due for execution
   */
  async getLinksDueForExecution(): Promise<DbRecurringPaymentLink[]> {
    return await this.repository.getDueForExecution();
  }

  /**
   * Mark a payment as successfully executed
   */
  async markPaymentSuccess(
    executionId: string,
    transactionHash: string,
  ): Promise<void> {
    const executions = await this.repository.findExecutionsByLinkId(executionId);
    const execution = executions.find(e => e.id === executionId);
    
    if (!execution) {
      throw new NotFoundException(`Execution not found: ${executionId}`);
    }

    await this.repository.updateExecutionStatus(executionId, ExecutionStatus.SUCCESS, {
      executedAt: new Date(),
      transactionHash,
    });

    // Increment executed count on the link
    const link = await this.repository.findById(execution.recurring_link_id);
    if (link) {
      // Check if we've reached the end
      const shouldComplete =
        (link.total_periods !== null && link.executed_count + 1 >= link.total_periods) ||
        (link.end_date && new Date(link.end_date) <= new Date());

      if (shouldComplete) {
        await this.repository.updateStatus(link.id, RecurringStatus.COMPLETED);
        this.logger.log(`Completed recurring payment link: ${link.id}`);
        
        this.eventEmitter.emit('recurring.link.completed', {
          linkId: link.id,
          totalExecuted: link.executed_count + 1,
        });
      } else {
        // Schedule next execution
        const nextDate = this.calculateNextExecutionDate(new Date(), link.frequency);
        await this.repository.createExecution({
          recurringLinkId: link.id,
          periodNumber: link.executed_count + 2,
          scheduledAt: nextDate,
          amount: link.amount,
          asset: link.asset,
        });
      }
    }

    this.logger.log(`Marked payment ${executionId} as successful`);

    // Emit event
    this.eventEmitter.emit('recurring.payment.executed', {
      executionId,
      transactionHash,
    });
  }

  /**
   * Mark a payment as failed
   */
  async markPaymentFailure(
    executionId: string,
    failureReason: string,
    retryCount: number,
  ): Promise<void> {
    const maxRetries = parseInt(process.env.RECURRING_PAYMENT_MAX_RETRY || '3');

    const executions = await this.repository.findExecutionsByLinkId(executionId);
    const execution = executions.find(e => e.id === executionId);
    
    if (!execution) {
      throw new NotFoundException(`Execution not found: ${executionId}`);
    }

    if (retryCount >= maxRetries) {
      // Max retries reached - mark as permanently failed
      await this.repository.updateExecutionStatus(executionId, ExecutionStatus.FAILED, {
        failureReason,
        retryCount,
        lastRetryAt: new Date(),
      });

      this.logger.error(`Payment ${executionId} failed permanently after ${retryCount} retries`);

      // Emit event
      this.eventEmitter.emit('recurring.payment.failed', {
        executionId,
        failureReason,
        permanent: true,
      });
    } else {
      // Schedule retry
      await this.repository.updateExecutionStatus(executionId, ExecutionStatus.PENDING, {
        failureReason,
        retryCount,
        lastRetryAt: new Date(),
      });

      this.logger.warn(`Payment ${executionId} failed, will retry (attempt ${retryCount}/${maxRetries})`);
    }
  }

  // ---------------------------------------------------------------------------
  // Private Helper Methods
  // ---------------------------------------------------------------------------

  private validateCreateDto(dto: CreateRecurringPaymentLinkDto): void {
    // Validate either username or destination is provided
    if (!dto.username && !dto.destination) {
      throw new LinkValidationError(
        LinkErrorCode.INVALID_DESTINATION,
        'Either username or destination must be provided',
        'username/destination',
      );
    }

    // Validate amount
    if (dto.amount <= 0) {
      throw new LinkValidationError(
        LinkErrorCode.INVALID_AMOUNT,
        'Amount must be greater than zero',
        'amount',
      );
    }

    // Validate asset
    if (!dto.asset || dto.asset.trim() === '') {
      throw new LinkValidationError(
        LinkErrorCode.ASSET_NOT_WHITELISTED,
        'Asset must be provided',
        'asset',
      );
    }

    // Validate frequency
    if (!Object.values(FrequencyType).includes(dto.frequency)) {
      throw new LinkValidationError(
        LinkErrorCode.INVALID_AMOUNT, // Reusing error code
        'Invalid frequency type',
        'frequency',
      );
    }

    // Validate dates
    if (dto.startDate && new Date(dto.startDate) < new Date()) {
      throw new LinkValidationError(
        LinkErrorCode.INVALID_AMOUNT,
        'Start date cannot be in the past',
        'startDate',
      );
    }

    if (dto.endDate && dto.startDate && new Date(dto.endDate) <= new Date(dto.startDate)) {
      throw new LinkValidationError(
        LinkErrorCode.INVALID_AMOUNT,
        'End date must be after start date',
        'endDate',
      );
    }

    // Validate total periods
    if (dto.totalPeriods !== undefined && dto.totalPeriods <= 0) {
      throw new LinkValidationError(
        LinkErrorCode.INVALID_AMOUNT,
        'Total periods must be greater than zero',
        'totalPeriods',
      );
    }
  }

  private validateUpdateDto(
    dto: UpdateRecurringPaymentLinkDto,
    existingLink: DbRecurringPaymentLink,
  ): void {
    // Cannot update completed or cancelled links
    if (
      existingLink.status === RecurringStatus.COMPLETED ||
      existingLink.status === RecurringStatus.CANCELLED
    ) {
      throw new BadRequestException(
        'Cannot update a completed or cancelled recurring link',
      );
    }

    // Validate amount if provided
    if (dto.amount !== undefined && dto.amount <= 0) {
      throw new BadRequestException('Amount must be greater than zero');
    }

    // Validate dates if provided
    if (dto.endDate) {
      const endDate = new Date(dto.endDate);
      if (endDate <= new Date()) {
        throw new BadRequestException('End date must be in the future');
      }
    }
  }

  calculateNextExecutionDate(currentDate: Date, frequency: FrequencyType): Date {
    const next = new Date(currentDate);

    switch (frequency) {
      case FrequencyType.DAILY:
        next.setDate(next.getDate() + 1);
        break;
      case FrequencyType.WEEKLY:
        next.setDate(next.getDate() + 7);
        break;
      case FrequencyType.MONTHLY:
        next.setMonth(next.getMonth() + 1);
        break;
      case FrequencyType.YEARLY:
        next.setFullYear(next.getFullYear() + 1);
        break;
    }

    return next;
  }

  private mapToResponseDto(
    link: DbRecurringPaymentLink,
    executions?: DbRecurringPaymentExecution[],
  ): RecurringPaymentLinkResponseDto {
    const response: RecurringPaymentLinkResponseDto = {
      id: link.id,
      username: link.username || undefined,
      destination: link.destination || undefined,
      amount: link.amount,
      asset: link.asset,
      assetIssuer: link.asset_issuer || undefined,
      frequency: link.frequency,
      startDate: new Date(link.start_date),
      endDate: link.end_date ? new Date(link.end_date) : undefined,
      totalPeriods: link.total_periods || undefined,
      executedCount: link.executed_count,
      nextExecutionDate: new Date(link.next_execution_date),
      status: link.status,
      memo: link.memo || undefined,
      memoType: link.memo_type || undefined,
      referenceId: link.reference_id || undefined,
      privacyEnabled: link.privacy_enabled,
      createdAt: new Date(link.created_at),
      updatedAt: new Date(link.updated_at),
    };

    if (executions) {
      response.executions = executions.map((exec) => this.mapExecutionToDto(exec));
    }

    return response;
  }

  private mapExecutionToDto(execution: DbRecurringPaymentExecution): RecurringPaymentExecutionDto {
    return {
      id: execution.id,
      periodNumber: execution.period_number,
      scheduledAt: new Date(execution.scheduled_at),
      executedAt: execution.executed_at ? new Date(execution.executed_at) : undefined,
      amount: execution.amount,
      asset: execution.asset,
      status: execution.status,
      transactionHash: execution.transaction_hash || undefined,
      failureReason: execution.failure_reason || undefined,
      retryCount: execution.retry_count,
      notificationSent: execution.notification_sent,
      createdAt: new Date(execution.created_at),
    };
  }
}
