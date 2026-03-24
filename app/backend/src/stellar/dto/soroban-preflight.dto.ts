import { IsNotEmpty, IsString, Matches } from "class-validator";
import { ApiProperty } from "@nestjs/swagger";

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
}
