import { IsInt, IsNotEmpty, IsOptional, IsString, Matches, Max, Min } from "class-validator";
import { Type } from "class-transformer";
import { ApiProperty, ApiPropertyOptional } from "@nestjs/swagger";

export class SorobanPreflightDto {
  @ApiProperty({
    description: "Any funded Stellar account used only to build & simulate the tx",
    example: "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF",
  })
  @IsString()
  @IsNotEmpty()
  @Matches(/^G[A-Z0-9]{55}$/, {
    message: "sourceAccount must be a valid Stellar public key",
  })
  sourceAccount!: string;

  @ApiPropertyOptional({
    description: "Expected on-chain contract deployment version asserted by the client",
    example: 1,
  })
  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  @Max(100000)
  contractVersion?: number;

  @ApiPropertyOptional({
    description: "Client contract schema version (semver)",
    example: "1.0.0",
  })
  @IsOptional()
  @IsString()
  schemaVersion?: string;

  @ApiPropertyOptional({
    description: "Target contract ID asserted by the client",
    example: "CD2J6K7T3YJ77QXZP3EXAMPLE",
  })
  @IsOptional()
  @IsString()
  contractId?: string;
}
