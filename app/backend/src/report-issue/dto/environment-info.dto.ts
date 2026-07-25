import { ApiProperty } from '@nestjs/swagger';
import { IsOptional, IsString, IsNumber } from 'class-validator';

/**
 * DTO for environment information in issue reports
 */
export class EnvironmentInfoDto {
  @ApiProperty({
    description: 'Platform (e.g., ios, android, web)',
    example: 'ios',
    required: false,
  })
  @IsOptional()
  @IsString()
  platform?: string;

  @ApiProperty({
    description: 'Platform version',
    example: '17.0',
    required: false,
  })
  @IsOptional()
  @IsString()
  platformVersion?: string;

  @ApiProperty({
    description: 'Application version',
    example: '1.2.3',
    required: false,
  })
  @IsOptional()
  @IsString()
  appVersion?: string;

  @ApiProperty({
    description: 'User agent string',
    example: 'Mozilla/5.0...',
    required: false,
  })
  @IsOptional()
  @IsString()
  userAgent?: string;

  @ApiProperty({
    description: 'User locale',
    example: 'en-US',
    required: false,
  })
  @IsOptional()
  @IsString()
  locale?: string;

  @ApiProperty({
    description: 'User timezone',
    example: 'America/Los_Angeles',
    required: false,
  })
  @IsOptional()
  @IsString()
  timezone?: string;

  @ApiProperty({
    description: 'Screen width in pixels',
    example: 390,
    required: false,
  })
  @IsOptional()
  @IsNumber()
  screenWidth?: number;

  @ApiProperty({
    description: 'Screen height in pixels',
    example: 844,
    required: false,
  })
  @IsOptional()
  @IsNumber()
  screenHeight?: number;
}
