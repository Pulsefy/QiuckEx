import { Type } from "class-transformer";
import {
  IsArray,
  IsNotEmpty,
  IsOptional,
  IsString,
  ValidateNested,
  ArrayMinSize,
  Matches,
} from "class-validator";
import { ApiProperty, ApiPropertyOptional } from "@nestjs/swagger";


export class PathAssetRefDto {
  @ApiProperty({ example: "USDC" })
  @IsString()
  @IsNotEmpty()
  code!: string;

  @ApiPropertyOptional({
    description: "Required for issued assets; omit for XLM",
    example:
      "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN",
  })
  @IsOptional()
  @IsString()
  issuer?: string | null;
}

export class PathPreviewRequestDto {
  @ApiProperty({
    description: "Human-readable amount the recipient should receive",
    example: "10.5",
  })
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

  @ApiProperty({
    type: [PathAssetRefDto],
    description: "Assets payers may use (strict-receive path search)",
  })
  @IsArray()
  @ArrayMinSize(1)
  @ValidateNested({ each: true })
  @Type(() => PathAssetRefDto)
  sourceAssets!: PathAssetRefDto[];
}

export class StrictSendPathPreviewRequestDto {
  @ApiProperty({
    description: "Human-readable amount the sender will send exactly",
    example: "10.5",
  })
  @IsString()
  @IsNotEmpty()
  @Matches(/^\d+(\.\d{1,14})?$/, {
    message: "sourceAmount must be a positive decimal number",
  })
  sourceAmount!: string;

  @ApiProperty({ type: PathAssetRefDto })
  @ValidateNested()
  @Type(() => PathAssetRefDto)
  sourceAsset!: PathAssetRefDto;

  @ApiProperty({
    type: [PathAssetRefDto],
    description: "Assets the recipient could receive (strict-send path search)",
  })
  @IsArray()
  @ArrayMinSize(1)
  @ValidateNested({ each: true })
  @Type(() => PathAssetRefDto)
  destinationAssets!: PathAssetRefDto[];
}
