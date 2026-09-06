import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
  ExportDeliveryMethod,
  ExportFormat,
  ExportStatus,
  ExportType,
} from '../enums/export.enums';

export class ExportStatusResponseDto {
  @ApiProperty({ description: 'Job ID for the export' })
  jobId!: string;

  @ApiProperty({ enum: ExportStatus, description: 'Current export status' })
  status!: ExportStatus;

  @ApiProperty({ enum: ExportType })
  exportType!: ExportType;

  @ApiProperty({ enum: ExportFormat })
  format!: ExportFormat;

  @ApiProperty({ enum: ExportDeliveryMethod })
  deliveryMethod!: ExportDeliveryMethod;

  @ApiProperty({
    description: 'When the export was queued',
    format: 'date-time',
  })
  queuedAt!: string;

  @ApiProperty({
    description: 'When processing started',
    format: 'date-time',
    nullable: true,
  })
  startedAt!: string | null;

  @ApiProperty({
    description: 'When processing completed',
    format: 'date-time',
    nullable: true,
  })
  completedAt!: string | null;

  @ApiProperty({
    description: 'When processing failed',
    format: 'date-time',
    nullable: true,
  })
  failedAt!: string | null;

  @ApiPropertyOptional({
    description: 'Delivery reference, present when status is completed',
  })
  deliveryReference?: string;

  @ApiPropertyOptional({
    description: 'Failure reason, present when status is failed',
  })
  failureReason?: string;
}
