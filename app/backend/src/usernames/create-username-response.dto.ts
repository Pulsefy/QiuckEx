import { ApiProperty } from '@nestjs/swagger';

/**
 * Response DTO for username creation
 */
export class CreateUsernameResponseDto {
  @ApiProperty({
    description: 'Indicates whether the operation was successful',
    example: true,
  })
  ok!: boolean;
}
