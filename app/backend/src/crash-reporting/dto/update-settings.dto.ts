import { IsBoolean } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

/**
 * DTO for updating crash reporting settings
 */
export class UpdateSettingsDto {
  @ApiProperty({
    description: 'Whether crash reporting is enabled',
    example: true,
  })
  @IsBoolean()
  enabled: boolean;
}
