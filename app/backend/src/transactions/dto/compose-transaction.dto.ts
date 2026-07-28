import {
  IsString,
  IsNotEmpty,
  IsOptional,
  IsArray,
  ValidateNested,
  MaxLength,
  IsEnum,
} from "class-validator";
import { Type } from "class-transformer";
import { MemoType } from "../../dto/validators/stellar-memo.validator";

export class ContractParamDto {
  @IsString()
  @IsNotEmpty()
  type: string;

  value: unknown;
}

export class CanonicalMemoDto {
  @IsEnum(['text', 'id', 'hash', 'return'])
  type: MemoType;
  
  @IsString()
  @IsNotEmpty()
  value: string;
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

  @ValidateNested()
  @Type(() => CanonicalMemoDto)
  @IsOptional()
  memo?: CanonicalMemoDto; // Canonical memo support
}

export class SubmitSignedTransactionDto {
  @IsString()
  @IsNotEmpty()
  signedXdr: string; // Already signed transaction envelope XDR

  @IsString()
  @IsOptional()
  networkPassphrase?: string; // Defaults to testnet

  @IsString()
  @IsNotEmpty()
  @MaxLength(128)
  idempotencyKey: string; // Required idempotency key for submit
}

export class SimulateOperationDto {
  @IsString()
  @IsNotEmpty()
  @MaxLength(128)
  contractId: string;

  @IsString()
  @IsNotEmpty()
  @MaxLength(64)
  method: string;

  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => ContractParamDto)
  params: ContractParamDto[];

  @IsString()
  @IsNotEmpty()
  sourceAccount: string;

  @IsString()
  @IsOptional()
  networkPassphrase?: string;

  @IsString()
  @IsOptional()
  simulateFailure?: string; // Optional: force specific failure scenario for testing
}