import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
  ArrayMaxSize,
  IsArray,
  IsBoolean,
  IsNumber,
  IsObject,
  IsOptional,
  IsString,
  Max,
  Min,
} from 'class-validator';

export interface FeatureFlagRecord {
  key: string;
  name: string;
  description: string;
  enabled: boolean;
  killSwitch: boolean;
  rolloutPercentage: number;
  allowedUsers: string[];
  environments: string[];
  metadata: Record<string, unknown>;
  updatedAt: string;
  updatedBy: string;
}

export interface FeatureFlagEvaluationContext {
  userId?: string;
  environment?: string;
}

export interface FeatureFlagEvaluationResult {
  key: string;
  enabled: boolean;
  reason:
    | 'enabled'
    | 'disabled'
    | 'kill-switch'
    | 'environment-mismatch'
    | 'allowlist-match'
    | 'rollout-match'
    | 'rollout-miss'
    | 'missing-user-context'
    | 'missing-flag';
  source: 'store' | 'bootstrap' | 'cache';
}

export interface FeatureFlagsListResponse {
  flags: FeatureFlagRecord[];
  source: 'store' | 'bootstrap' | 'cache';
  storeAvailable: boolean;
}

export class UpdateFeatureFlagDto {
  @ApiPropertyOptional({ description: 'Human-readable display name' })
  @IsOptional()
  @IsString()
  name?: string;

  @ApiPropertyOptional({ description: 'Feature flag description' })
  @IsOptional()
  @IsString()
  description?: string;

  @ApiPropertyOptional({ description: 'Master enabled toggle' })
  @IsOptional()
  @IsBoolean()
  enabled?: boolean;

  @ApiPropertyOptional({ description: 'Emergency kill switch' })
  @IsOptional()
  @IsBoolean()
  killSwitch?: boolean;

  @ApiPropertyOptional({ description: 'Deterministic rollout percentage', minimum: 0, maximum: 100 })
  @IsOptional()
  @IsNumber()
  @Min(0)
  @Max(100)
  rolloutPercentage?: number;

  @ApiPropertyOptional({ description: 'Explicit user allowlist', type: [String] })
  @IsOptional()
  @IsArray()
  @ArrayMaxSize(500)
  @IsString({ each: true })
  allowedUsers?: string[];

  @ApiPropertyOptional({ description: 'Allowed environments', type: [String] })
  @IsOptional()
  @IsArray()
  @ArrayMaxSize(20)
  @IsString({ each: true })
  environments?: string[];

  @ApiPropertyOptional({ description: 'Arbitrary flag metadata', type: Object })
  @IsOptional()
  @IsObject()
  metadata?: Record<string, unknown>;
}

export class FeatureFlagQueryDto {
  @ApiPropertyOptional({ description: 'User identifier for deterministic rollout evaluation' })
  @IsOptional()
  @IsString()
  userId?: string;

  @ApiPropertyOptional({ description: 'Runtime environment (defaults to server NODE_ENV)' })
  @IsOptional()
  @IsString()
  environment?: string;
}

export class EvaluateFeatureFlagResponseDto {
  @ApiProperty()
  key!: string;

  @ApiProperty()
  enabled!: boolean;

  @ApiProperty()
  reason!: string;

  @ApiProperty()
  source!: string;
}
