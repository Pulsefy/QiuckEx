import { ApiProperty, ApiPropertyOptional } from "@nestjs/swagger";
import {
  IsNotEmpty,
  IsOptional,
  IsString,
  IsInt,
  Min,
  Max,
  Matches,
} from "class-validator";
import { Type } from "class-transformer";

export class GetTransactionsQueryDto {
  @ApiProperty({
    description: "Stellar account ID (public key)",
    example: "GD...",
  })
  @IsNotEmpty()
  @IsString()
  @Matches(/^G[A-Z2-7]{55}$/, { message: "Invalid Stellar account ID format" })
  accountId: string;

  @ApiPropertyOptional({
    description: "Asset code and issuer (e.g., XLM or USDC:GA...)",
    example: "USDC:GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335XOP3IA2M65BZDCCXN2YRC2TH",
  })
  @IsOptional()
  @IsString()
  @Matches(/^(XLM|[A-Z0-9]{1,12}:G[A-Z2-7]{55})$/, {
    message: "Invalid asset format. Use XLM or CODE:ISSUER",
  })
  asset?: string;

  @ApiPropertyOptional({
    description: "Maximum number of transactions to return",
    minimum: 1,
    maximum: 200,
    default: 20,
  })
  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  @Max(200)
  limit?: number = 20;

  @ApiPropertyOptional({
    description: "Cursor for pagination (paging_token)",
  })
  @IsOptional()
  @IsString()
  cursor?: string;
}

export class TransactionItemDto {
  @ApiProperty({ example: "100.5000000" })
  amount: string;

  @ApiProperty({ example: "XLM" })
  asset: string;

  @ApiPropertyOptional({ example: "Payment for services" })
  memo?: string;

  @ApiProperty({ example: "2026-02-21T08:00:00Z" })
  timestamp: string;

  @ApiProperty({ example: "6852...a341" })
  txHash: string;

  @ApiProperty({ example: "1234567890" })
  pagingToken: string;
}

export class TransactionResponseDto {
  @ApiProperty({
    type: [TransactionItemDto],
    description: "List of transaction items",
  })
  items: TransactionItemDto[];

  @ApiPropertyOptional({
    description: "Cursor for the next page",
    example: "1234567890",
  })
  nextCursor?: string;
}
