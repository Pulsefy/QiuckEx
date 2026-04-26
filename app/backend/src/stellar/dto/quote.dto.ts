import { Type } from "class-transformer";
import {
  IsArray,
  IsBoolean,
  IsInt,
  IsNotEmpty,
  IsOptional,
  IsString,
  Max,
  Min,
  ValidateNested,
  ArrayMinSize,
  Matches,
} from "class-validator";
import { ApiProperty, ApiPropertyOptional } from "@nestjs/swagger";

import { PathAssetRefDto } from "./path-preview.dto";

export class CreateQuoteDto {
  @ApiProperty({ example: "10.5", description: "Amount the recipient receives" })
  @IsString()
  @IsNotEmpty()
  @Matches(/^\d+(\.\d{1,14})?$/, {
    message: "destinationAmount must be a positive decimal number",
  })
  destinationAmount!: string;

  @ApiProperty({ type: PathAssetRefDto })
  @ValidateNested()
  @Type(() => PathAssetRefDto)
  destinationAsset!: PathAssetRefDto;

  @ApiProperty({ type: [PathAssetRefDto], description: "Assets the sender may use" })
  @IsArray()
  @ArrayMinSize(1)
  @ValidateNested({ each: true })
  @Type(() => PathAssetRefDto)
  sourceAssets!: PathAssetRefDto[];

  @ApiPropertyOptional({
    description: "Maximum slippage in basis points (1 bps = 0.01%). Default: 50 (0.5%)",
    example: 50,
    minimum: 0,
    maximum: 10000,
  })
  @IsOptional()
  @IsInt()
  @Min(0)
  @Max(10000)
  maxSlippageBps?: number;

  @ApiPropertyOptional({
    description: "Quote TTL in seconds. Default: 30",
    example: 30,
    minimum: 5,
    maximum: 300,
  })
  @IsOptional()
  @IsInt()
  @Min(5)
  @Max(300)
  ttlSeconds?: number;

  @ApiPropertyOptional({
    description: "Run Soroban preflight simulation to verify transaction feasibility",
    example: false,
  })
  @IsOptional()
  @IsBoolean()
  preflight?: boolean;
}

export class QuotePathDto {
  @ApiProperty() sourceAsset!: string;
  @ApiProperty() sourceAmount!: string;
  @ApiProperty() sourceAmountWithSlippage!: string;
  @ApiProperty() destinationAsset!: string;
  @ApiProperty() destinationAmount!: string;
  @ApiProperty({ type: [String] }) pathHops!: string[];
  @ApiProperty() rateDescription!: string;
}

export class QuoteResponseDto {
  @ApiProperty({ description: "Unique quote ID" }) quoteId!: string;
  @ApiProperty({ type: [QuotePathDto] }) paths!: QuotePathDto[];
  @ApiProperty({ description: "ISO timestamp when this quote expires" }) expiresAt!: string;
  @ApiProperty({ description: "Slippage tolerance in basis points" }) maxSlippageBps!: number;
  @ApiProperty({ description: "Horizon URL used for path search" }) horizonUrl!: string;
  @ApiPropertyOptional({ description: "Preflight simulation result, if requested" })
  preflight?: { feasible: boolean; error?: string };
}
