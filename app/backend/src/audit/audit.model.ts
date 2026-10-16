import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class AuditLogDto {
  @ApiProperty({ description: 'Audit log identifier', example: '550e8400-e29b-41d4-a716-446655440000' })
  id: string;

  @ApiProperty({ description: 'Actor performing the action', example: 'admin_key_123' })
  actor: string;

  @ApiProperty({ description: 'Action performed', example: 'invite_team_member' })
  action: string;

  @ApiPropertyOptional({ description: 'Target entity or identifier', example: 'user_456' })
  target?: string;

  @ApiPropertyOptional({ description: 'Metadata dictionary', type: Object })
  metadata?: Record<string, unknown>;

  @ApiPropertyOptional({ description: 'HTTP request ID', example: 'req_123' })
  requestId?: string;

  @ApiProperty({ description: 'Log creation timestamp', example: '2026-01-01T00:00:00.000Z' })
  createdAt: Date;
}

export interface AuditLog extends AuditLogDto {}

export class QueryAuditLogsDto {
  @ApiPropertyOptional({ description: 'Filter by action' })
  action?: string;

  @ApiPropertyOptional({ description: 'Filter by actor' })
  actor?: string;

  @ApiPropertyOptional({ description: 'Start timestamp ISO string' })
  startTime?: string;

  @ApiPropertyOptional({ description: 'End timestamp ISO string' })
  endTime?: string;

  @ApiPropertyOptional({ description: 'Page number', default: 1, example: 1 })
  page?: number;

  @ApiPropertyOptional({ description: 'Limit per page', default: 50, example: 50 })
  limit?: number;
}

export class QueryAuditLogsResponseDto {
  @ApiProperty({ type: [AuditLogDto], description: 'List of matching audit logs' })
  data: AuditLogDto[];

  @ApiProperty({ description: 'Total number of matching audit logs', example: 100 })
  total: number;

  @ApiProperty({ description: 'Current page', example: 1 })
  page: number;

  @ApiProperty({ description: 'Limit per page', example: 50 })
  limit: number;
}

export class ApplyRetentionResponseDto {
  @ApiProperty({ description: 'Number of purged logs', example: 15 })
  deletedCount: number;
}


