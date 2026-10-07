import { IsString, IsOptional, IsArray, ValidateNested } from 'class-validator';
import { Type } from 'class-transformer';

export class AttachmentDto {
  @IsString()
  url: string;

  @IsString()
  @IsOptional()
  filename?: string;
}

export class FeedbackDto {
  @IsString()
  category: string;

  @IsString()
  title: string;

  @IsString()
  description: string;

  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => AttachmentDto)
  attachments: AttachmentDto[];

  // New fields for the issue
  @IsString()
  environment: string;

  @IsString()
  reproduction: string;
}
