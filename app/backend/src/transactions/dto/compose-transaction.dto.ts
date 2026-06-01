import {
  IsString,
  IsNotEmpty,
  IsOptional,
  IsArray,
  ValidateNested,
  MaxLength,
} from "class-validator";
import { Type } from "class-transformer";

export class ContractParamDto {
  @IsString()
  @IsNotEmpty()
  type: string;

  value: unknown;
}

export class ComposeTransactionDto {
  @IsString()
  @IsNotEmpty()
  @MaxLength(128)
  contractId: string; // C... Strkey contract address

  @IsString()
  @IsNotEmpty()
  @MaxLength(64)
  method: string; // Contract function name

  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => ContractParamDto)
  params: ContractParamDto[];

  @IsString()
  @IsNotEmpty()
  sourceAccount: string; // G... Strkey public key (no private key)

  @IsString()
  @IsOptional()
  networkPassphrase?: string; // Defaults to testnet

  @IsString()
  @IsOptional()
  @MaxLength(128)
  idempotencyKey?: string;
}
