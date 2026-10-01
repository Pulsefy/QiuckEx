import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class ExportStatusDto {
  @ApiProperty({ description: 'Export job identifier' })
  exportId: string;

  @ApiProperty({ enum: ['queued', 'running', 'completed', 'failed'] })
  status: 'queued' | 'running' | 'completed' | 'failed';

  @ApiProperty({ format: 'date-time' })
  createdAt: string;

  @ApiPropertyOptional({ format: 'date-time', nullable: true })
  startedAt: string | null;

  @ApiPropertyOptional({ format: 'date-time', nullable: true })
  completedAt: string | null;

  @ApiPropertyOptional({ description: 'Stable reference for retrieving the completed export' })
  deliveryReference?: string;

  @ApiPropertyOptional({ description: 'Failure reason when export generation fails' })
  failureReason?: string;
}