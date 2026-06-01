import { ApiProperty } from '@nestjs/swagger';

/**
 * DTO for log export response
 */
export class LogExportDto {
  @ApiProperty({
    description: 'User ID',
    example: 'user-123',
  })
  userId: string;

  @ApiProperty({
    description: 'When the logs were exported',
    example: '2026-05-26T10:00:00Z',
  })
  exportedAt: Date;

  @ApiProperty({
    description: 'Current redacted log lines',
    example: ['[INFO] Request received', '[INFO] Processing payment'],
    type: [String],
  })
  currentLogs: string[];

  @ApiProperty({
    description: 'Recent crash reports',
    type: 'array',
    items: {
      type: 'object',
      properties: {
        id: { type: 'string', example: 'report-123' },
        timestamp: { type: 'string', example: '2026-05-26T10:00:00Z' },
        error: {
          type: 'object',
          properties: {
            name: { type: 'string', example: 'Error' },
            message: { type: 'string', example: 'Connection failed' },
            stack: { type: 'string', example: 'Error: Connection failed\n  at ...' },
          },
        },
        context: { type: 'object', example: { route: '/api/payments' } },
        logLines: { type: 'array', items: { type: 'string' } },
      },
    },
  })
  crashReports: Array<{
    id: string;
    timestamp: Date;
    error: {
      name: string;
      message: string;
      stack?: string;
    };
    context?: Record<string, unknown>;
    logLines: string[];
  }>;
}
