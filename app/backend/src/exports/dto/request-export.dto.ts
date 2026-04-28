/**
 * Request Export DTO
 * 
 * Data transfer object for export request endpoint.
 */

import { IsString, IsEnum, IsObject, IsOptional } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

/**
 * Request Export DTO
 * 
 * Defines the structure for export requests.
 */
export class RequestExportDto {
  @ApiProperty({
    description: 'User ID requesting the export',
    example: '123e4567-e89b-12d3-a456-426614174000',
  })
  @IsString()
  userId: string;

  @ApiProperty({
    description: 'Type of data to export',
    enum: ['transactions', 'links', 'payments'],
    example: 'transactions',
  })
  @IsEnum(['transactions', 'links', 'payments'])
  exportType: 'transactions' | 'links' | 'payments';

  @ApiProperty({
    description: 'Filters to apply to the export query',
    example: { status: 'completed', startDate: '2024-01-01' },
    required: false,
  })
  @IsObject()
  @IsOptional()
  filters?: Record<string, unknown>;

  @ApiProperty({
    description: 'Output format for the export',
    enum: ['csv', 'json'],
    example: 'csv',
  })
  @IsEnum(['csv', 'json'])
  format: 'csv' | 'json';

  @ApiProperty({
    description: 'How to deliver the export',
    enum: ['webhook', 'email', 'download'],
    example: 'download',
  })
  @IsEnum(['webhook', 'email', 'download'])
  deliveryMethod: 'webhook' | 'email' | 'download';
}
