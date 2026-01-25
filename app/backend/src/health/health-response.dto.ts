import { ApiProperty } from '@nestjs/swagger';

/**
 * Health check response DTO
 */
export class HealthResponseDto {
  @ApiProperty({
    description: 'Health status of the service',
    example: 'ok',
    enum: ['ok'],
  })
  status!: 'ok';
}
