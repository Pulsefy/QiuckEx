import { IsIn, IsNotEmpty, IsObject, IsOptional, IsString, MaxLength } from 'class-validator';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export const ARTIFACT_TYPES = ['deploy_manifest', 'smoke_report', 'registry_snapshot'] as const;
export type DeploymentArtifactType = (typeof ARTIFACT_TYPES)[number];

export class UploadDeploymentArtifactDto {
  @ApiProperty({ example: 'deploy-2026-07-10-001' })
  @IsString()
  @IsNotEmpty()
  @MaxLength(128)
  deploymentId!: string;

  @ApiProperty({ enum: ARTIFACT_TYPES })
  @IsIn(ARTIFACT_TYPES)
  artifactType!: DeploymentArtifactType;

  @ApiProperty({
    description: 'Base64-encoded artifact content',
  })
  @IsString()
  @IsNotEmpty()
  contentBase64!: string;

  @ApiPropertyOptional({
    description: 'Network the deployment targeted; defaults to the server active network',
  })
  @IsOptional()
  @IsString()
  network?: string;

  @ApiPropertyOptional({ type: Object })
  @IsOptional()
  @IsObject()
  metadata?: Record<string, unknown>;
}

export class DeploymentArtifactResponseDto {
  @ApiProperty() id!: string;
  @ApiProperty() deploymentId!: string;
  @ApiProperty() network!: string;
  @ApiProperty({ enum: ARTIFACT_TYPES }) artifactType!: DeploymentArtifactType;
  @ApiProperty() checksumSha256!: string;
  @ApiProperty() sizeBytes!: number;
  @ApiProperty() uploadedBy!: string;
  @ApiPropertyOptional({ type: Object }) metadata?: Record<string, unknown>;
  @ApiProperty() createdAt!: string;
  @ApiProperty() retentionUntil!: string;
}

export class DeploymentArtifactDownloadResponseDto extends DeploymentArtifactResponseDto {
  @ApiProperty({ description: 'Base64-encoded artifact content' })
  contentBase64!: string;
  @ApiProperty({
    description: 'Whether the stored checksum matched a fresh SHA-256 of the content on read',
  })
  checksumValid!: boolean;
}

export class ListDeploymentArtifactsQueryDto {
  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  deploymentId?: string;

  @ApiPropertyOptional({ enum: ARTIFACT_TYPES })
  @IsOptional()
  @IsIn(ARTIFACT_TYPES)
  artifactType?: DeploymentArtifactType;
}
