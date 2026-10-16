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
  Post,
  Body,
  Param,
  Query,
  ParseIntPipe,
  DefaultValuePipe,
  HttpCode,
  HttpStatus,
} from "@nestjs/common";
import { ApiTags, ApiOperation, ApiOkResponse, ApiParam } from "@nestjs/swagger";
import { ReceiptsService } from "./receipts.service";
import { ReceiptHashService } from "./receipt-hash.service";
import {
  GetReceiptsByAddressDto,
  VerifyReceiptHashDto,
  ReceiptResponse,
  ReceiptListResponse,
  VerifyReceiptHashResponse,
} from "./dto/receipt.dto";
import { RateLimitTier } from "../auth/decorators/rate-limit-group.decorator";
import {
  RequiresIndexerLagCheck,
  IndexerLagPolicy,
} from "../indexer-lag/requires-indexer-lag-check.decorator";

@ApiTags("receipts")
@Controller("v1/receipts")
export class ReceiptsController {
  constructor(
    private readonly receiptsService: ReceiptsService,
    private readonly receiptHashService: ReceiptHashService,
  ) {}

  /**
   * GET /v1/receipts/tx/:txHash
   * GET /v1/receipts/tx/:txHash?operationIndex=1
   *
   * Returns a single normalized receipt for a transaction.
   * operationIndex defaults to 0 (first operation).
   * Response includes `receiptHash` — a deterministic SHA-256 hash of
   * canonical transaction data, stable across retries.
   */
  @Get("tx/:txHash")
  @RateLimitTier("public-read")
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: "Get normalized receipt by transaction hash",
    description: "Returns a single normalized receipt for a transaction and operation index.",
  })
  @ApiParam({ name: "txHash", description: "Stellar transaction hash" })
  @ApiOkResponse({
    description: "Normalized receipt response",
    type: ReceiptResponse,
  })
  // Joins live Horizon/RPC data against the indexed `receipts` table. A
  // receipt that silently omits its indexed metadata reads as a valid receipt
  // with fewer fields, so this route fails closed rather than degrading.
  @RequiresIndexerLagCheck(IndexerLagPolicy.FAIL_CLOSED)
  async getByTxHash(
    @Param("txHash") txHash: string,
    @Query("operationIndex", new DefaultValuePipe(0), ParseIntPipe)
    operationIndex: number,
  ): Promise<ReceiptResponse> {
    const receipt = await this.receiptsService.getByTxHash({
      txHash,
      operationIndex,
    });
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
  @Get("address/:address")
  @RateLimitTier("search")
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: "Get normalized receipts for an address",
    description: "Returns a paginated list of normalized receipts for a Stellar address.",
  })
  @ApiParam({ name: "address", description: "Stellar account address" })
  @ApiOkResponse({
    description: "Paginated receipts response",
    type: ReceiptListResponse,
  })
  // A receipt history list is a browse surface: entries are ordered newest
  // first and the caller can re-poll, so serving a slightly stale list with an
  // explicit staleness header is better than failing the whole page.
  @RequiresIndexerLagCheck(IndexerLagPolicy.STALE_HEADER)
  async getByAddress(
    @Param("address") address: string,
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

  /**
   * POST /v1/receipts/verify-hash
   *
   * Verifies that a receipt hash matches the provided canonical inputs.
   * Used by indexers and support tooling to validate receipt integrity
   * without needing to fetch the full receipt.
   *
   * Deliberately NOT decorated with @RequiresIndexerLagCheck(): this route is
   * a pure function of the caller's own body and touches no indexed data, so
   * indexer state cannot make its answer wrong. Blocking it would stop callers
   * from verifying integrity precisely when the indexer is misbehaving.
   */
  @Post("verify-hash")
  @RateLimitTier("mutation")
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: "Verify receipt hash against canonical inputs",
    description: "Verifies that a receipt hash matches the provided canonical inputs.",
  })
  @ApiOkResponse({
    description: "Hash verification result",
    type: VerifyReceiptHashResponse,
  })
  async verifyHash(
    @Body() dto: VerifyReceiptHashDto,
  ): Promise<VerifyReceiptHashResponse> {
    const { receiptHash, ...inputs } = dto;
    const computedHash = this.receiptHashService.computeHash(inputs);
    return {
      valid: computedHash === receiptHash,
      computedHash,
      providedHash: receiptHash,
    };
  }
}

