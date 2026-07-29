/**
 * ReceiptsController
 *
 * Exposes the receipt normalization API.
 * All endpoints return NormalizedReceipt — no client-side joins needed.
 *
 * Location: app/backend/src/receipts/receipts.controller.ts
 */

import {
  Controller,
  Get,
  Param,
  Query,
  ParseIntPipe,
  DefaultValuePipe,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import { ReceiptsService } from './receipts.service';
import { GetReceiptsByAddressDto, ReceiptResponse, ReceiptListResponse } from './dto/receipt.dto';

@Controller('v1/receipts')
export class ReceiptsController {
  constructor(private readonly receiptsService: ReceiptsService) {}

  /**
   * GET /v1/receipts/tx/:txHash
   * GET /v1/receipts/tx/:txHash?operationIndex=1
   *
   * Returns a single normalized receipt for a transaction.
   * operationIndex defaults to 0 (first operation).
   */
  @Get('tx/:txHash')
  @HttpCode(HttpStatus.OK)
  async getByTxHash(
    @Param('txHash') txHash: string,
    @Query('operationIndex', new DefaultValuePipe(0), ParseIntPipe)
    operationIndex: number,
  ): Promise<ReceiptResponse> {
    const receipt = await this.receiptsService.getByTxHash({ txHash, operationIndex });
    return { receipt };
  }

  /**
   * GET /v1/receipts/address/:address
   *
   * Returns a paginated list of normalized receipts for a Stellar address.
   *
   * Query params:
   *   type?     payment | refund | contract_action
   *   status?   success | pending | failed
   *   limit?    default 20, max 100
   *   cursor?   paging token from previous response
   */
  @Get('address/:address')
  @HttpCode(HttpStatus.OK)
  async getByAddress(
    @Param('address') address: string,
    @Query() query: Partial<GetReceiptsByAddressDto>,
  ): Promise<ReceiptListResponse> {
    const result = await this.receiptsService.getByAddress({
      address,
      type: query.type,
      status: query.status,
      limit: query.limit ?? 20,
      cursor: query.cursor,
    });
    return result;
  }
}