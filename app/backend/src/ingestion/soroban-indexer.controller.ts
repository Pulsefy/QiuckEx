import {
  Body,
  Controller,
  ConflictException,
  Get,
  HttpCode,
  HttpStatus,
  Post,
  Param,
  Query,
} from "@nestjs/common";
import { ApiOperation, ApiResponse, ApiTags } from "@nestjs/swagger";
import { IsBoolean, IsInt, IsNotEmpty, IsOptional, IsString, Min, IsArray } from "class-validator";

import { SorobanEventIndexerService, LedgerRangeResult } from "./soroban-event-indexer.service";
import type { UnparsedSorobanEventRecord, UnparsedSorobanEventReason } from "./unparsed-soroban-event.repository";

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

class ReplayBatchDto {
  @IsArray()
  @IsString({ each: true })
  pagingTokens!: string[];
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
        undefined,
        dto.force ?? false,
      );
    } finally {
      this.running = false;
    }
  }

  @Get("unparsed-events")
  @ApiOperation({
    summary: "List pending unparsed Soroban events with filters",
    description:
      "Returns raw contract events retained because their schema version was unknown or parsing failed. " +
      "Filter by contractId, schemaVersion, and errorType (unknown_schema_version or parse_failure).",
  })
  @ApiResponse({ status: 200, description: "Pending unparsed events" })
  listUnparsed(
    @Query("limit") limit?: string,
    @Query("contractId") contractId?: string,
    @Query("schemaVersion") schemaVersion?: string,
    @Query("errorType") errorType?: UnparsedSorobanEventReason,
  ): Promise<UnparsedSorobanEventRecord[]> {
    return this.indexer.listUnparsedEvents(Number(limit ?? 100), {
      contractId,
      schemaVersion: schemaVersion ? Number(schemaVersion) : undefined,
      errorType,
    });
  }

  @Post("unparsed-events/replay")
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: "Replay pending unparsed Soroban events (batch by limit)",
    description:
      "Attempts to parse and persist retained raw events after schema support has been updated.",
  })
  @ApiResponse({ status: 200, description: "Replay completed" })
  replayUnparsed(@Query("limit") limit?: string) {
    return this.indexer.replayUnparsedEvents(Number(limit ?? 100));
  }

  @Post("unparsed-events/:pagingToken/replay")
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: "Replay a single specific unparsed Soroban event",
    description:
      "Attempts to parse and persist a single retained raw event after schema support has been updated.",
  })
  @ApiResponse({ status: 200, description: "Replay result" })
  replaySingle(@Param("pagingToken") pagingToken: string) {
    return this.indexer.replaySingleEvent(pagingToken);
  }

  @Post("unparsed-events/replay/batch")
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: "Replay a specific batch of unparsed Soroban events",
    description:
      "Attempts to parse and persist a specific list of retained raw events by their paging tokens.",
  })
  @ApiResponse({ status: 200, description: "Replay completed" })
  async replaySpecificBatch(@Body() dto: ReplayBatchDto) {
    return this.indexer.replaySpecificBatch(dto.pagingTokens);
  }
}