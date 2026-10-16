import { ApiProperty, ApiPropertyOptional } from "@nestjs/swagger";

export class IndexerStatusResponseDto {
  @ApiProperty({ type: Number, nullable: true })
  currentNetworkLedger!: number | null;

  @ApiProperty({ type: Number, nullable: true })
  lastIndexedLedger!: number | null;

  @ApiProperty({ type: Number, nullable: true })
  lagLedgers!: number | null;

  @ApiProperty({ type: Boolean })
  isLagging!: boolean;

  @ApiProperty({ type: Boolean })
  isEnabled!: boolean;

  @ApiProperty({ type: Boolean })
  isOverridden!: boolean;

  @ApiProperty({ type: Number })
  thresholdLedgers!: number;
}

export class IngestionStatusResponseDto {
  @ApiProperty({ type: Number, nullable: true })
  currentNetworkLedger!: number | null;

  @ApiProperty({ type: Number, nullable: true })
  lastIndexedLedger!: number | null;

  @ApiProperty({ type: Number, nullable: true })
  lagLedgers!: number | null;

  @ApiProperty({ type: Boolean })
  isLagging!: boolean;

  @ApiProperty({ type: Number })
  thresholdLedgers!: number;
}

export class WebhookBacklogResponseDto {
  @ApiProperty({ type: Number })
  totalPending!: number;

  @ApiProperty({ type: [Object] })
  backlog!: unknown[];
}

export class RecentErrorItemDto {
  @ApiProperty({ type: String })
  id!: string;

  @ApiProperty({ type: String })
  action!: string;

  @ApiProperty({ type: String, nullable: true })
  actor!: string | null;

  @ApiProperty({ type: String, nullable: true })
  requestId?: string | null;

  @ApiProperty({ type: String })
  createdAt!: string;
}

export class RecentErrorsResponseDto {
  @ApiProperty({ type: Number })
  total!: number;

  @ApiProperty({ type: Number })
  page!: number;

  @ApiProperty({ type: Number })
  limit!: number;

  @ApiProperty({ type: [RecentErrorItemDto] })
  errors!: RecentErrorItemDto[];
}
