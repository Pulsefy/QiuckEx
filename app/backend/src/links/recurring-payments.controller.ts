import {
  Controller,
  Get,
  Post,
  Patch,
  Body,
  Param,
  Query,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiParam, ApiQuery } from '@nestjs/swagger';
import { RecurringPaymentsService } from './recurring-payments.service';
import {
  CreateRecurringPaymentLinkDto,
  UpdateRecurringPaymentLinkDto,
  RecurringPaymentLinkResponseDto,
  ListRecurringPaymentsResponseDto,
  QueryRecurringPaymentsDto,
  RecurringStatus,
  RecurringPaymentExecutionDto,
} from './dto/recurring-payment.dto';

@ApiTags('recurring-payments')
@Controller('links/recurring')
export class RecurringPaymentsController {
  constructor(private readonly service: RecurringPaymentsService) {}

  // ---------------------------------------------------------------------------
  // CRUD Operations
  // ---------------------------------------------------------------------------

  @Post()
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({
    summary: 'Create a new recurring payment link',
    description: 'Creates a subscription-style payment link with specified frequency and duration',
  })
  @ApiResponse({
    status: 201,
    description: 'Recurring payment link created successfully',
    type: RecurringPaymentLinkResponseDto,
  })
  @ApiResponse({
    status: 400,
    description: 'Invalid input parameters',
  })
  async createRecurringLink(
    @Body() dto: CreateRecurringPaymentLinkDto,
  ): Promise<{ success: boolean; data: RecurringPaymentLinkResponseDto }> {
    const result = await this.service.createRecurringLink(dto);
    return {
      success: true,
      data: result,
    };
  }

  @Get(':id')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Get recurring payment link by ID',
    description: 'Retrieves details of a specific recurring payment link including execution history',
  })
  @ApiParam({ name: 'id', description: 'Recurring payment link ID' })
  @ApiResponse({
    status: 200,
    description: 'Recurring payment link retrieved successfully',
    type: RecurringPaymentLinkResponseDto,
  })
  @ApiResponse({
    status: 404,
    description: 'Recurring payment link not found',
  })
  async getRecurringLink(
    @Param('id') id: string,
  ): Promise<{ success: boolean; data: RecurringPaymentLinkResponseDto }> {
    const result = await this.service.getRecurringLinkById(id);
    return {
      success: true,
      data: result,
    };
  }

  @Get()
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'List recurring payment links',
    description: 'Lists all recurring payment links with optional filtering',
  })
  @ApiQuery({ name: 'status', required: false, enum: RecurringStatus })
  @ApiQuery({ name: 'username', required: false })
  @ApiQuery({ name: 'destination', required: false })
  @ApiQuery({ name: 'cursor', required: false, description: 'Opaque pagination cursor' })
  @ApiQuery({ name: 'limit', required: false, type: Number, description: 'Items per page (1-100)' })
  @ApiResponse({
    status: 200,
    description: 'Recurring payment links listed successfully',
    type: ListRecurringPaymentsResponseDto,
  })
  async listRecurringLinks(
    @Query() query: QueryRecurringPaymentsDto,
  ): Promise<{ success: boolean; data: RecurringPaymentLinkResponseDto[]; total: number; next_cursor: string | null; has_more: boolean; limit: number }> {
    const result = await this.service.listRecurringLinks(query);
    return {
      success: true,
      ...result,
    };
  }

  @Patch(':id')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Update recurring payment link',
    description: 'Updates an existing recurring payment link',
  })
  @ApiParam({ name: 'id', description: 'Recurring payment link ID' })
  @ApiResponse({
    status: 200,
    description: 'Recurring payment link updated successfully',
    type: RecurringPaymentLinkResponseDto,
  })
  @ApiResponse({
    status: 400,
    description: 'Invalid update parameters or link cannot be updated',
  })
  @ApiResponse({
    status: 404,
    description: 'Recurring payment link not found',
  })
  async updateRecurringLink(
    @Param('id') id: string,
    @Body() dto: UpdateRecurringPaymentLinkDto,
  ): Promise<{ success: boolean; data: RecurringPaymentLinkResponseDto }> {
    const result = await this.service.updateRecurringLink(id, dto);
    return {
      success: true,
      data: result,
    };
  }

  // ---------------------------------------------------------------------------
  // Status Management
  // ---------------------------------------------------------------------------

  @Post(':id/cancel')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Cancel recurring payment link',
    description: 'Cancels a recurring payment link, stopping all future payments',
  })
  @ApiParam({ name: 'id', description: 'Recurring payment link ID' })
  @ApiResponse({
    status: 200,
    description: 'Recurring payment link cancelled successfully',
    type: RecurringPaymentLinkResponseDto,
  })
  @ApiResponse({
    status: 400,
    description: 'Link is already cancelled',
  })
  @ApiResponse({
    status: 404,
    description: 'Recurring payment link not found',
  })
  async cancelRecurringLink(
    @Param('id') id: string,
  ): Promise<{ success: boolean; data: RecurringPaymentLinkResponseDto }> {
    const result = await this.service.cancelRecurringLink(id);
    return {
      success: true,
      data: result,
    };
  }

  @Post(':id/pause')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Pause recurring payment link',
    description: 'Temporarily suspends a recurring payment link',
  })
  @ApiParam({ name: 'id', description: 'Recurring payment link ID' })
  @ApiResponse({
    status: 200,
    description: 'Recurring payment link paused successfully',
    type: RecurringPaymentLinkResponseDto,
  })
  @ApiResponse({
    status: 400,
    description: 'Link is not active',
  })
  @ApiResponse({
    status: 404,
    description: 'Recurring payment link not found',
  })
  async pauseRecurringLink(
    @Param('id') id: string,
  ): Promise<{ success: boolean; data: RecurringPaymentLinkResponseDto }> {
    const result = await this.service.pauseRecurringLink(id);
    return {
      success: true,
      data: result,
    };
  }

  @Post(':id/resume')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Resume recurring payment link',
    description: 'Resumes a previously paused recurring payment link',
  })
  @ApiParam({ name: 'id', description: 'Recurring payment link ID' })
  @ApiResponse({
    status: 200,
    description: 'Recurring payment link resumed successfully',
    type: RecurringPaymentLinkResponseDto,
  })
  @ApiResponse({
    status: 400,
    description: 'Link is not paused',
  })
  @ApiResponse({
    status: 404,
    description: 'Recurring payment link not found',
  })
  async resumeRecurringLink(
    @Param('id') id: string,
  ): Promise<{ success: boolean; data: RecurringPaymentLinkResponseDto }> {
    const result = await this.service.resumeRecurringLink(id);
    return {
      success: true,
      data: result,
    };
  }

  // ---------------------------------------------------------------------------
  // Execution History
  // ---------------------------------------------------------------------------

  @Get(':id/executions')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Get execution history',
    description: 'Retrieves the execution history for a recurring payment link',
  })
  @ApiParam({ name: 'id', description: 'Recurring payment link ID' })
  @ApiResponse({
    status: 200,
    description: 'Execution history retrieved successfully',
  })
  @ApiResponse({
    status: 404,
    description: 'Recurring payment link not found',
  })
  async getExecutionHistory(
    @Param('id') id: string,
  ): Promise<{ success: boolean; data: RecurringPaymentExecutionDto[] }> {
    const executions = await this.service.getExecutionHistory(id);
    return {
      success: true,
      data: executions,
    };
  }
}
