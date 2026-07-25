import { ApiProperty } from '@nestjs/swagger';
import { IsString, IsNumber, IsOptional } from 'class-validator';

/**
 * DTO for attachment reference in issue reports
 */
export class AttachmentReferenceDto {
  @ApiProperty({
    description: 'Attachment ID',
    example: 'att_1234567890',
  })
  @IsString()
  id!: string;

  @ApiProperty({
    description: 'Attachment name',
    example: 'screenshot.png',
  })
  @IsString()
  name!: string;

  @ApiProperty({
    description: 'Attachment MIME type',
    example: 'image/png',
  })
  @IsString()
  type!: string;

  @ApiProperty({
    description: 'Attachment size in bytes',
    example: 102400,
  })
  @IsNumber()
  size!: number;

  @ApiProperty({
    description: 'Attachment URL (if uploaded)',
    example: 'https://storage.example.com/attachments/att_1234567890.png',
    required: false,
  })
  @IsOptional()
  @IsString()
  url?: string;
}
