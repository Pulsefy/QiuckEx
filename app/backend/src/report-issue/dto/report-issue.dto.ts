import { ApiProperty } from '@nestjs/swagger';
import { EnvironmentInfoDto } from './environment-info.dto';
import { AttachmentReferenceDto } from './attachment-reference.dto';

/**
 * DTO for issue report response
 */
export class ReportIssueDto {
  @ApiProperty({
    description: 'The report ID',
    example: 'report_1234567890',
  })
  id!: string;

  @ApiProperty({
    description: 'User ID (if provided)',
    example: 'user_1234567890',
    required: false,
  })
  userId?: string;

  @ApiProperty({
    description: 'Type of issue',
    example: 'bug',
  })
  issueType!: string;

  @ApiProperty({
    description: 'Issue title',
    example: 'Payment link not working',
  })
  title!: string;

  @ApiProperty({
    description: 'Detailed description',
    example: 'When I click on the payment link, nothing happens',
  })
  description!: string;

  @ApiProperty({
    description: 'Environment information',
    type: EnvironmentInfoDto,
  })
  environment!: EnvironmentInfoDto;

  @ApiProperty({
    description: 'Steps to reproduce',
    example: '1. Open the app\n2. Navigate to payment link\n3. Click on link',
    required: false,
  })
  reproduction?: string;

  @ApiProperty({
    description: 'Additional context (redacted)',
    example: { linkId: 'link_123' },
    required: false,
  })
  context?: Record<string, unknown>;

  @ApiProperty({
    description: 'Attachment references',
    type: [AttachmentReferenceDto],
    required: false,
  })
  attachments?: AttachmentReferenceDto[];

  @ApiProperty({
    description: 'Redacted payload for storage',
    example: {},
  })
  redactedPayload!: Record<string, unknown>;

  @ApiProperty({
    description: 'Creation timestamp',
    example: '2024-01-15T10:30:00.000Z',
  })
  createdAt!: Date;
}
