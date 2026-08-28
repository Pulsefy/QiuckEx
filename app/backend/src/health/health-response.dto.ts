import { ApiProperty, ApiPropertyOptional } from "@nestjs/swagger";
import { DependencyStatus } from "./health.service";

export class DependencyCheckDto {
  @ApiProperty({ enum: ["healthy", "degraded", "unhealthy"], example: "healthy" })
  status!: DependencyStatus;

  @ApiPropertyOptional({ example: 125 })
  latency?: number;

  @ApiPropertyOptional({ example: "Connection timeout" })
  error?: string;

  @ApiPropertyOptional({ example: "2024-01-01T00:00:00.000Z" })
  lastSuccess?: string;
}

export class HealthResponseDto {
  @ApiProperty({ enum: ["healthy", "degraded", "unhealthy"], example: "healthy" })
  status!: string;

  @ApiProperty({ example: "0.1.0" })
  version!: string;

  @ApiProperty({ example: 3600, description: "Uptime in seconds" })
  uptime!: number;

  @ApiProperty({ example: "2024-01-01T00:00:00.000Z" })
  timestamp!: string;

  @ApiProperty({
    type: Object,
    additionalProperties: { $ref: "#/components/schemas/DependencyCheckDto" },
    example: {
      supabase: { status: "healthy", latency: 40 },
      horizon: { status: "healthy", latency: 80 },
      soroban_rpc: { status: "healthy", latency: 55 },
      redis: { status: "healthy", latency: 10 },
    },
  })
  checks!: Record<string, DependencyCheckDto>;
}

export class ReadyCheckDto {
  @ApiProperty({ example: "supabase" })
  name!: string;

  @ApiProperty({ enum: ["healthy", "degraded", "unhealthy"] })
  status!: DependencyStatus;

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

  @ApiProperty({ enum: ["healthy", "degraded", "unhealthy"], example: "healthy" })
  status!: string;

  @ApiProperty({ example: "2024-01-01T00:00:00.000Z", description: "Timestamp of the readiness check" })
  timestamp!: string;

  @ApiProperty({
    type: Object,
    additionalProperties: { $ref: "#/components/schemas/DependencyCheckDto" },
  })
  checks!: Record<string, DependencyCheckDto>;
}
