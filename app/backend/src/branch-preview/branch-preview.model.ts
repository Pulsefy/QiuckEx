import { ApiProperty } from '@nestjs/swagger';

export interface BranchPreviewEnvironment {
  id: string;
  branchName: string;
  apiUrl: string;
  frontendUrl: string;
  network: 'testnet' | 'mainnet';
  contractRegistryVersion: string;
  isActive: boolean;
  isShared: boolean;
  expiryExempt: boolean;
  createdAt: Date;
  updatedAt: Date;
  lastActivityAt?: Date;
  expiresAt?: Date;
  autoExpiredAt?: Date;
  autoExpiryReason?: string;
}

export interface CreateBranchPreviewDto {
  branchName: string;
  apiUrl: string;
  frontendUrl: string;
  network: 'testnet' | 'mainnet';
  contractRegistryVersion: string;
  ttlMs?: number;
  isShared?: boolean;
  expiryExempt?: boolean;
}

export interface UpdateBranchPreviewDto {
  apiUrl?: string;
  frontendUrl?: string;
  network?: 'testnet' | 'mainnet';
  contractRegistryVersion?: string;
  isActive?: boolean;
  ttlMs?: number;
  isShared?: boolean;
  expiryExempt?: boolean;
}

export class BranchPreviewResponseDto {
  @ApiProperty()
  branchName: string;
  
  @ApiProperty()
  apiUrl: string;
  
  @ApiProperty()
  frontendUrl: string;
  
  @ApiProperty()
  network: string;
  
  @ApiProperty()
  contractRegistryVersion: string;
  
  @ApiProperty({ required: false })
  isFallback?: boolean;
}

export interface ListBranchPreviewsDto {
  page?: number;
  limit?: number;
  includeInactive?: boolean;
}