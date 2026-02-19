import { ApiProperty } from "@nestjs/swagger";

export class HealthResponseDto {
  @ApiProperty({ enum: ["ok", "degraded"] })
  status!: "ok" | "degraded";

  @ApiProperty({
    example: {
      supabase: "up",
      horizon: "up",
    },
  })
  services!: {
    supabase: "up" | "down";
    horizon: "up" | "down";
  };
}
