import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsNotEmpty, IsOptional, IsString, IsInt, Min, Max, Matches } from 'class-validator';
import { Type } from 'class-transformer';

export class GetTransactionsQueryDto {
  @ApiProperty({
    description: 'Stellar account ID (public key)',
    example: 'GD...',
  })
  @IsNotEmpty()
  @IsString()
  @Matches(/^G[A-Z2-7]{55}$/, { message: 'Invalid Stellar account ID format' })
  accountId: string;

  @ApiPropertyOptional({
    description: 'Asset code and issuer (e.g., XLM or USDC:GA...)',
    example: 'USDC:GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335XOP3IA2M65BZDCCXN2YRC2TH',
  })
  @IsOptional()
  @IsString()
  @Matches(/^(XLM|[A-Z0-9]{1,12}:G[A-Z2-7]{55})$/, {
    message: 'Invalid asset format. Use XLM or CODE:ISSUER',
  })
  asset?: string;

  @ApiPropertyOptional({
    description: 'Maximum number of transactions to return',
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
    description: 'Cursor for pagination (paging_token)',
  })
  @IsOptional()
  @IsString()
  cursor?: string;
}

export class TransactionItemDto {
  @ApiProperty()
  amount: string;

  @ApiProperty()
  asset: string;

  @ApiPropertyOptional()
  memo?: string;

  @ApiProperty()
  timestamp: string;

  @ApiProperty()
  txHash: string;

  @ApiProperty()
  pagingToken: string;
}

export class TransactionResponseDto {
  @ApiProperty({ type: [TransactionItemDto] })
  items: TransactionItemDto[];

  @ApiPropertyOptional({ description: 'Cursor for the next page' })
  nextCursor?: string;
}
