import { ApiProperty } from '@nestjs/swagger';

/**
 * DTO for crash report response
 */
export class CrashReportDto {
  @ApiProperty({
    description: 'Crash report ID',
    example: 'report-123',
  })
  id: string;

  @ApiProperty({
    description: 'User ID (optional)',
    example: 'user-123',
    required: false,
  })
  userId?: string;

  @ApiProperty({
    description: 'Redacted error information',
    example: {
      name: 'Error',
      message: 'Connection failed',
      stack: 'Error: Connection failed\n  at ...',
    },
  })
  error: {
    name: string;
    message: string;
    stack?: string;
  };

  @ApiProperty({
    description: 'Redacted context information',
    example: { route: '/api/payments', method: 'POST' },
    required: false,
  })
  context?: Record<string, unknown>;

  @ApiProperty({
    description: 'Redacted log lines',
    example: ['[INFO] Request received', '[ERROR] Connection failed'],
    type: [String],
  })
  logLines: string[];

  @ApiProperty({
    description: 'When the crash occurred',
    example: '2026-05-26T10:00:00Z',
  })
  timestamp: Date;

  @ApiProperty({
    description: 'When the report was created',
    example: '2026-05-26T10:00:01Z',
  })
  createdAt: Date;
}
