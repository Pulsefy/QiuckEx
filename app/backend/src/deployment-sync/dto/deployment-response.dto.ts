import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

import { BranchDeployment } from '../deployment-sync.model';

export class BranchDeploymentResponseDto {
  @ApiProperty() id!: string;
  @ApiProperty() branchName!: string;
  @ApiPropertyOptional() prNumber?: number;
  @ApiProperty() commitSha!: string;
  @ApiProperty() previewUrl!: string;
  @ApiProperty({ enum: ['in_progress', 'deployed', 'failed', 'cancelled'] })
  status!: BranchDeployment['status'];
  @ApiProperty() environment!: string;
  @ApiProperty() deliveredAt!: string;
  @ApiProperty() createdAt!: string;
  @ApiProperty() updatedAt!: string;
}
