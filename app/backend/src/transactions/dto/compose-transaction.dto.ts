import {
  IsString,
  IsNotEmpty,
  IsOptional,
  IsArray,
  ValidateNested,
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
  contractId: string; // C... Strkey contract address

  @IsString()
  @IsNotEmpty()
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
}
