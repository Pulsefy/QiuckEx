import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
  IsDateString,
  IsEnum,
  IsInt,
  IsNotEmpty,
  IsOptional,
  IsString,
  IsUrl,
  Matches,
  MaxLength,
  Min,
} from 'class-validator';

import { BRANCH_DEPLOYMENT_STATUSES, BranchDeploymentStatus } from '../deployment-sync.model';

export class SyncBranchDeploymentDto {
  @ApiProperty({
    description: 'Git branch name the deployment was created for',
    example: 'feat/be-branch-metadata-sync',
  })
  @IsString()
  @IsNotEmpty()
  @MaxLength(256)
  branchName!: string;

  @ApiPropertyOptional({
    description: 'Pull request number when the deployment belongs to a PR branch',
    example: 544,
  })
  @IsOptional()
  @IsInt()
  @Min(1)
  prNumber?: number;

  @ApiProperty({
    description: 'Git commit SHA that was deployed',
    example: 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2',
  })
  @IsString()
  @Matches(/^[a-fA-F0-9]{7,64}$/)
  commitSha!: string;

  @ApiProperty({
    description: 'Public preview URL for the deployment',
    example: 'https://preview-544.quickex.to',
  })
  @IsUrl({ require_tld: false })
  previewUrl!: string;

  @ApiProperty({
    description: 'Deployment status',
    enum: BRANCH_DEPLOYMENT_STATUSES,
    example: 'deployed',
  })
  @IsEnum(BRANCH_DEPLOYMENT_STATUSES)
  status!: BranchDeploymentStatus;

  @ApiPropertyOptional({
    description: 'Deployment environment name',
    default: 'preview',
    example: 'preview',
  })
  @IsOptional()
  @IsString()
  @IsNotEmpty()
  @MaxLength(64)
  environment?: string;

  @ApiPropertyOptional({
    description:
      'ISO 8601 timestamp of the deployment event. Used to reject stale out-of-order deliveries.',
    example: '2026-08-25T00:00:00.000Z',
  })
  @IsOptional()
  @IsDateString()
  deliveredAt?: string;
}
