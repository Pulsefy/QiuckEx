import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsObject } from 'class-validator';

import { SmokeScenariosArtifact } from '../smoke-scenarios.types';

export class ConsumeSmokeScenariosDto {
  @ApiProperty({
    type: Object,
    description: 'Raw smoke-scenarios artifact JSON (quickex-smoke-scenarios-v1)',
  })
  @IsObject()
  artifact!: Record<string, unknown>;
}

export class SmokeScenariosValidationResultDto {
  @ApiProperty({ description: 'Whether the artifact is valid' })
  valid!: boolean;

  @ApiProperty({ type: [String], description: 'Field-level validation errors' })
  errors!: string[];

  @ApiPropertyOptional({
    type: Object,
    description: 'Normalized artifact returned when valid',
  })
  artifact?: SmokeScenariosArtifact;
}
