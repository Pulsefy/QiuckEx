import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsNotEmpty, IsOptional, IsString, MaxLength } from 'class-validator';

export class SubmitIssueReportDto {
  @ApiProperty({
    description: 'Description of the issue',
    example: 'I encountered an error when trying to submit a transaction',
  })
  @IsString()
  @IsNotEmpty()
  @MaxLength(5000)
  userMessage: string;

  @ApiPropertyOptional({
    description: 'Error details / stack trace',
    example: 'TypeError: Cannot read properties of undefined...',
  })
  @IsString()
  @IsOptional()
  errorDetails?: string;

  @ApiPropertyOptional({
    description: 'Browser / environment metadata',
    example: 'Chrome 120, Windows 11, testnet',
  })
  @IsString()
  @IsOptional()
  environment?: string;

  @ApiPropertyOptional({
    description: 'Page route where the issue occurred',
    example: '/dashboard',
  })
  @IsString()
  @IsOptional()
  route?: string;
}
