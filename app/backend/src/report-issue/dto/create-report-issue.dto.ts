import { ApiProperty } from '@nestjs/swagger';
import { IsString, IsNotEmpty, IsOptional, IsArray, ValidateNested, IsObject } from 'class-validator';
import { Type } from 'class-transformer';
import { EnvironmentInfoDto } from './environment-info.dto';
import { AttachmentReferenceDto } from './attachment-reference.dto';

/**
 * DTO for creating a new issue report
 * 
 * @example
 * ```json
 * {
 *   "issueType": "bug",
 *   "title": "Payment link not working",
 *   "description": "When I click on the payment link, nothing happens",
 *   "environment": {
 *     "platform": "ios",
 *     "platformVersion": "17.0",
 *     "appVersion": "1.2.3"
 *   },
 *   "reproduction": "1. Open the app\n2. Navigate to payment link\n3. Click on link",
 *   "context": {
 *     "linkId": "link_123"
 *   },
 *   "attachments": [
 *     {
 *       "id": "att_123",
 *       "name": "screenshot.png",
 *       "type": "image/png",
 *       "size": 102400
 *     }
 *   ]
 * }
 * ```
 */
export class CreateReportIssueDto {
  @ApiProperty({
    description: 'User ID (optional, for authenticated users)',
    example: 'user_1234567890',
    required: false,
  })
  @IsOptional()
  @IsString()
  userId?: string;

  @ApiProperty({
    description: 'Type of issue (e.g., bug, feature_request, abuse_report, other)',
    example: 'bug',
  })
  @IsString()
  @IsNotEmpty()
  issueType!: string;

  @ApiProperty({
    description: 'Issue title',
    example: 'Payment link not working',
  })
  @IsString()
  @IsNotEmpty()
  title!: string;

  @ApiProperty({
    description: 'Detailed description of the issue',
    example: 'When I click on the payment link, nothing happens',
  })
  @IsString()
  @IsNotEmpty()
  description!: string;

  @ApiProperty({
    description: 'Environment information',
    type: EnvironmentInfoDto,
  })
  @IsObject()
  @ValidateNested()
  @Type(() => EnvironmentInfoDto)
  environment!: EnvironmentInfoDto;

  @ApiProperty({
    description: 'Steps to reproduce the issue',
    example: '1. Open the app\n2. Navigate to payment link\n3. Click on link',
    required: false,
  })
  @IsOptional()
  @IsString()
  reproduction?: string;

  @ApiProperty({
    description: 'Additional context (will be redacted)',
    example: { linkId: 'link_123' },
    required: false,
  })
  @IsOptional()
  @IsObject()
  context?: Record<string, unknown>;

  @ApiProperty({
    description: 'Attachment references',
    type: [AttachmentReferenceDto],
    required: false,
  })
  @IsOptional()
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => AttachmentReferenceDto)
  attachments?: AttachmentReferenceDto[];
}
