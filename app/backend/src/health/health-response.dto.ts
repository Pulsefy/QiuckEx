import { ApiProperty } from "@nestjs/swagger";

export class HealthResponseDto {
  @ApiProperty({ example: "ok" })
  status!: string;

  @ApiProperty({ example: "0.1.0" })
  version!: string;

  @ApiProperty({ example: 3600, description: "Uptime in seconds" })
  uptime!: number;
}

export class ReadyCheckDto {
  @ApiProperty({ example: "supabase" })
  name!: string;

  @ApiProperty({ enum: ["up", "down"] })
  status!: "up" | "down";

  @ApiProperty({ example: "125ms", required: false })
  latency?: string;

  @ApiProperty({ example: ["All critical env variables loaded"], required: false, type: [String] })
  details?: string[];

  @ApiProperty({ example: "2024-01-01T00:00:00.000Z", required: false })
  lastSuccess?: string;

  @ApiProperty({ example: "Connection timeout", required: false })
  error?: string;

  @ApiProperty({ example: 5, required: false, description: "Lag in seconds for ingestion checks" })
  lagSeconds?: number;
}

export class ReadyResponseDto {
  @ApiProperty({ example: true })
  ready!: boolean;

  @ApiProperty({ example: "2024-01-01T00:00:00.000Z", description: "Timestamp of the readiness check" })
  timestamp!: string;

  @ApiProperty({ type: [ReadyCheckDto] })
  checks!: ReadyCheckDto[];
}
