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
}

export class ReadyResponseDto {
  @ApiProperty({ example: true })
  ready!: boolean;

  @ApiProperty({ type: [ReadyCheckDto] })
  checks!: ReadyCheckDto[];
}
