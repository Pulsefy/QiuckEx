import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsString, IsOptional, IsArray, ValidateNested } from 'class-validator';
import { Type } from 'class-transformer';

export class AttachmentDto {
  @ApiProperty({ description: 'Attachment URL', example: 'https://example.com/file.png' })
  @IsString()
  url: string;

  @ApiPropertyOptional({ description: 'Attachment filename', example: 'screenshot.png' })
  @IsString()
  @IsOptional()
  filename?: string;
}

export class FeedbackDto {
  @ApiProperty({ description: 'Feedback category', example: 'bug' })
  @IsString()
  category: string;

  @ApiProperty({ description: 'Feedback title', example: 'Payment link issue' })
  @IsString()
  title: string;

  @ApiProperty({ description: 'Detailed feedback description', example: 'Error when submitting' })
  @IsString()
  description: string;

  @ApiProperty({ type: [AttachmentDto], description: 'List of attachments' })
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => AttachmentDto)
  attachments: AttachmentDto[];

  @ApiProperty({ description: 'Environment name', example: 'production' })
  @IsString()
  environment: string;

  @ApiProperty({ description: 'Reproduction steps', example: '1. Navigate to...' })
  @IsString()
  reproduction: string;
}

export class CreateFeedbackResponseDto {
  @ApiProperty({ description: 'Response message', example: 'Feedback submitted' })
  message: string;

  @ApiProperty({ description: 'Feedback record ID', example: '550e8400-e29b-41d4-a716-446655440000' })
  id: string;
}

export class StoredFeedbackDto extends FeedbackDto {
  @ApiProperty({ description: 'Feedback ID', example: '550e8400-e29b-41d4-a716-446655440000' })
  id: string;

  @ApiPropertyOptional({ description: 'Submitter IP address', example: '127.0.0.1' })
  ipAddress?: string;

  @ApiProperty({ description: 'Submission timestamp', example: '2026-01-01T00:00:00.000Z' })
  createdAt: Date;
}

