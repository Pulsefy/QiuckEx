import { ApiProperty, ApiPropertyOptional } from "@nestjs/swagger";
import {
  IsBoolean,
  IsEnum,
  IsInt,
  IsOptional,
  IsString,
  Max,
  Min,
} from "class-validator";

export class AdminVerifyAssetDto {
  @ApiProperty({ description: "Asset code (e.g., USDC, XLM)", example: "USDC" })
  @IsString()
  code: string;

  @ApiPropertyOptional({
    description: "Asset issuer public key (null for native XLM)",
    example: "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN",
  })
  @IsOptional()
  @IsString()
  issuer?: string;

  @ApiPropertyOptional({
    description: "Asset type",
    enum: ["native", "credit_alphanum4", "credit_alphanum12"],
    default: "credit_alphanum4",
  })
  @IsOptional()
  @IsEnum(["native", "credit_alphanum4", "credit_alphanum12"])
  type?: "native" | "credit_alphanum4" | "credit_alphanum12";

  @ApiPropertyOptional({
    description: "Number of decimal places (typically 7 for Stellar assets)",
    default: 7,
  })
  @IsOptional()
  @IsInt()
  @Min(0)
  @Max(14)
  decimals?: number;

  @ApiPropertyOptional({
    description: "URL to the asset icon image",
    example: "https://example.com/icon.png",
  })
  @IsOptional()
  @IsString()
  iconUrl?: string;

  @ApiProperty({
    description: "Whether the asset is marked as verified",
    example: true,
  })
  @IsBoolean()
  verified: boolean;
}
