import { ApiProperty } from "@nestjs/swagger";

export class PublicStatusComponentDto {
  @ApiProperty({ example: "horizon" })
  name!: string;

  @ApiProperty({
    enum: ["operational", "degraded", "down"],
    example: "operational",
  })
  status!: "operational" | "degraded" | "down";

  @ApiProperty({ example: "Network: testnet", required: false })
  detail?: string;
}

export class PublicStatusResponseDto {
  @ApiProperty({
    example: "operational",
    description: "Overall platform status",
  })
  status!: "operational" | "degraded" | "down";

  @ApiProperty({ example: "testnet", description: "Stellar network name" })
  network!: string;

  @ApiProperty({
    example: 12345678,
    description: "Last processed ledger sequence",
  })
  lastLedger!: number;

  @ApiProperty({ example: "2024-01-01T00:00:00.000Z" })
  timestamp!: string;

  @ApiProperty({ type: [PublicStatusComponentDto] })
  components!: PublicStatusComponentDto[];

  @ApiProperty({ example: "0.1.0" })
  version!: string;
}
