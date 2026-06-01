import {
  Body,
  Controller,
  ConflictException,
  HttpCode,
  HttpStatus,
  Post,
} from "@nestjs/common";
import { ApiOperation, ApiResponse, ApiTags } from "@nestjs/swagger";
import { IsBoolean, IsInt, IsNotEmpty, IsOptional, IsString, Min } from "class-validator";

import { SorobanEventIndexerService, LedgerRangeResult } from "./soroban-event-indexer.service";

class ReindexDto {
  @IsString()
  @IsNotEmpty()
  contractId!: string;

  @IsInt()
  @Min(1)
  fromLedger!: number;

  @IsInt()
  @Min(1)
  toLedger!: number;

  /**
   * When true, ignores the stored checkpoint and re-processes the full range.
   * Idempotent upserts ensure no duplicate records are created.
   */
  @IsBoolean()
  @IsOptional()
  force?: boolean;
}

/**
 * Admin endpoint for triggering Soroban event reindexing over a ledger range.
 * Should be protected by an API-key guard in production.
 */
@ApiTags("indexer")
@Controller("indexer")
export class SorobanIndexerController {
  private running = false;

  constructor(private readonly indexer: SorobanEventIndexerService) {}

  @Post("reindex")
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: "Reindex Soroban contract events for a ledger range (admin only)",
    description:
      "Fetches and persists all contract events in [fromLedger, toLedger]. " +
      "Safe to call multiple times — idempotent upserts prevent duplicates. " +
      "Set force=true to ignore the stored checkpoint and reprocess the full range.",
  })
  @ApiResponse({ status: 200, description: "Reindex completed" })
  @ApiResponse({ status: 409, description: "A reindex run is already in progress" })
  async reindex(@Body() dto: ReindexDto): Promise<LedgerRangeResult> {
    if (this.running) {
      throw new ConflictException("A reindex run is already in progress");
    }

    this.running = true;
    try {
      return await this.indexer.indexLedgerRange(
        dto.contractId,
        dto.fromLedger,
        dto.toLedger,
        dto.force ?? false,
      );
    } finally {
      this.running = false;
    }
  }
}
