import {
  Controller,
  Post,
  Get,
  Param,
  Body,
  HttpCode,
  HttpStatus,
  UseGuards,
  Req,
  Query,
} from '@nestjs/common';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiHeader,
  ApiQuery,
} from '@nestjs/swagger';
import { Request } from 'express';
import { RefundsService } from './refunds.service';
import { InitiateRefundDto } from './dto/initiate-refund.dto';
import { ApiKeyGuard } from '../auth/guards/api-key.guard';
import { RequireScopes } from '../auth/decorators/require-scopes.decorator';

interface ApiKeyRequest extends Request {
  apiKey: { id: string };
}

@ApiTags('admin/refunds')
@ApiHeader({
  name: 'X-API-Key',
  description: 'Admin API key with refunds:write scope',
  required: true,
})
@UseGuards(ApiKeyGuard)
@RequireScopes('refunds:write')
@Controller('admin/refunds')
export class RefundsController {
  constructor(private readonly refundsService: RefundsService) {}

  @Post()
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Initiate a refund (idempotent)' })
  @ApiResponse({ status: 200, description: 'Refund attempt created or existing attempt returned' })
  @ApiResponse({ status: 409, description: 'Entity is not in a refundable state' })
  async initiate(
    @Body() dto: InitiateRefundDto,
    @Req() req: ApiKeyRequest,
  ) {
    const actorId: string = req.apiKey.id;
    return this.refundsService.initiateRefund(dto, actorId);
  }

  @Post(':id/approve')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Approve a pending refund' })
  @ApiResponse({ status: 200, description: 'Refund approved' })
  @ApiResponse({ status: 409, description: 'Refund is not in pending state' })
  async approve(
    @Param('id') id: string,
    @Req() req: ApiKeyRequest,
  ) {
    const actorId: string = req.apiKey.id;
    return this.refundsService.approveRefund(id, actorId);
  }

  @Post(':id/reject')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Reject a pending refund' })
  @ApiResponse({ status: 200, description: 'Refund rejected' })
  @ApiResponse({ status: 409, description: 'Refund is not in pending state' })
  async reject(
    @Param('id') id: string,
    @Body() body: { notes?: string },
    @Req() req: ApiKeyRequest,
  ) {
    const actorId: string = req.apiKey.id;
    return this.refundsService.rejectRefund(id, actorId, body.notes);
  }

  @Get()
  @ApiOperation({ summary: 'List all refund attempts' })
  @ApiQuery({ name: 'cursor', required: false, description: 'Opaque pagination cursor' })
  @ApiQuery({ name: 'limit', required: false, type: Number, description: 'Items per page (1-100)' })
  @ApiResponse({ status: 200, description: 'List of refund attempts' })
  async list(
    @Query('cursor') cursor?: string,
    @Query('limit') limit?: number,
  ) {
    return this.refundsService.listRefunds(cursor, Number(limit || 20));
  }
}
