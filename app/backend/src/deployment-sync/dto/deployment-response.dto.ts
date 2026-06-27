import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class DeploymentResponseDto {
  @ApiProperty({
    description: 'Unique identifier for the deployment metadata entry',
    example: '550e8400-e29b-41d4-a716-446655440000',
  })
  id!: string;

  @ApiProperty({
    description: 'The name of the branch',
    example: 'feat/be-branch-metadata-sync',
  })
  branchName!: string;

  @ApiPropertyOptional({
    description: 'The pull request number associated with this branch deployment',
    example: 42,
    nullable: true,
  })
  prNumber!: number | null;

  @ApiProperty({
    description: 'The git commit SHA of the deployment',
    example: 'a1b2c3d4e5f6g7h8i9j0a1b2c3d4e5f6g7h8i9j0',
  })
  commitSha!: string;

  @ApiPropertyOptional({
    description: 'The preview URL for the deployment environment',
    example: 'https://quickex-preview-pr-42.vercel.app',
    nullable: true,
  })
  previewUrl!: string | null;

  @ApiProperty({
    description: 'The status of the deployment',
    example: 'success',
  })
  status!: string;

  @ApiProperty({
    description: 'The ISO timestamp of the deployment or git event',
    example: '2026-06-27T08:00:00.000Z',
  })
  eventTimestamp!: string;

  @ApiProperty({
    description: 'When the record was first created in the database',
    example: '2026-06-27T08:00:05.123Z',
  })
  createdAt!: string;

  @ApiProperty({
    description: 'When the record was last updated in the database',
    example: '2026-06-27T08:05:00.456Z',
  })
  updatedAt!: string;
}
