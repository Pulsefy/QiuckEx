import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsNotEmpty, IsString, IsOptional, IsInt, IsISO8601 } from 'class-validator';

export class DeploymentWebhookPayloadDto {
  @ApiProperty({
    description: 'The name of the branch',
    example: 'feat/be-branch-metadata-sync',
  })
  @IsString()
  @IsNotEmpty()
  branchName!: string;

  @ApiPropertyOptional({
    description: 'The pull request number associated with this branch deployment',
    example: 42,
  })
  @IsOptional()
  @IsInt()
  prNumber?: number;

  @ApiProperty({
    description: 'The git commit SHA of the deployment',
    example: 'a1b2c3d4e5f6g7h8i9j0a1b2c3d4e5f6g7h8i9j0',
  })
  @IsString()
  @IsNotEmpty()
  commitSha!: string;

  @ApiPropertyOptional({
    description: 'The preview URL for the deployment environment',
    example: 'https://quickex-preview-pr-42.vercel.app',
  })
  @IsOptional()
  @IsString()
  previewUrl?: string;

  @ApiProperty({
    description: 'The deployment status (e.g. pending, success, failed)',
    example: 'success',
  })
  @IsString()
  @IsNotEmpty()
  status!: string;

  @ApiProperty({
    description: 'The ISO timestamp of the deployment or git event',
    example: '2026-06-27T08:00:00.000Z',
  })
  @IsISO8601()
  @IsNotEmpty()
  eventTimestamp!: string;
}
