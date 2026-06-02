import { ApiProperty } from '@nestjs/swagger';

/**
 * DTO for crash reporting settings response
 */
export class SettingsDto {
  @ApiProperty({
    description: 'User ID',
    example: 'user-123',
  })
  userId: string;

  @ApiProperty({
    description: 'Whether crash reporting is enabled',
    example: true,
  })
  crashReportingEnabled: boolean;

  @ApiProperty({
    description: 'When the settings were last updated',
    example: '2026-05-26T10:00:00Z',
  })
  updatedAt: Date;
}
