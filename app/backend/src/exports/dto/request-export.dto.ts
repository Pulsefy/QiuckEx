import {
  IsString,
  IsEnum,
  IsObject,
  IsOptional,
  IsNotEmpty,
} from 'class-validator';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
  ExportDeliveryMethod,
  ExportFormat,
  ExportType,
} from '../enums/export.enums';

export class RequestExportDto {
  @ApiProperty({
    description: 'User ID requesting the export',
    example: '123e4567-e89b-12d3-a456-426614174000',
  })
  @IsString()
  @IsNotEmpty()
  userId!: string;

  @ApiProperty({
    description: 'Type of data to export',
    enum: ExportType,
    example: ExportType.TRANSACTIONS,
  })
  @IsEnum(ExportType)
  exportType!: ExportType;

  @ApiPropertyOptional({
    description: 'Filters to apply to the export query',
    example: { status: 'completed', startDate: '2024-01-01' },
  })
  @IsObject()
  @IsOptional()
  filters?: Record<string, unknown>;

  @ApiProperty({
    description: 'Output format for the export',
    enum: ExportFormat,
    example: ExportFormat.CSV,
  })
  @IsEnum(ExportFormat)
  format!: ExportFormat;

  @ApiProperty({
    description: 'How to deliver the export',
    enum: ExportDeliveryMethod,
    example: ExportDeliveryMethod.DOWNLOAD,
  })
  @IsEnum(ExportDeliveryMethod)
  deliveryMethod!: ExportDeliveryMethod;
}
