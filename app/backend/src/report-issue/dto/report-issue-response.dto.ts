import { ApiProperty } from '@nestjs/swagger';

/**
 * DTO for report issue submission response
 */
export class ReportIssueResponseDto {
  @ApiProperty({
    description: 'The created report ID',
    example: 'report_1234567890',
  })
  id!: string;

  @ApiProperty({
    description: 'Success message',
    example: 'Issue report submitted successfully',
  })
  message!: string;
}
