import { Body, Controller, HttpCode, HttpStatus, Post, UseGuards } from '@nestjs/common';
import { ApiHeader, ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';

import { RequireScopes } from '../../auth/decorators/require-scopes.decorator';
import { ApiKeyGuard } from '../../auth/guards/api-key.guard';
import {
  ConsumeSmokeScenariosDto,
  SmokeScenariosValidationResultDto,
} from './dto/smoke-scenarios.dto';
import { SmokeScenariosService } from './smoke-scenarios.service';

@ApiTags('contracts')
@ApiHeader({
  name: 'X-API-Key',
  description: 'Admin-scoped API key required to validate smoke-scenarios artifacts.',
  required: true,
})
@UseGuards(ApiKeyGuard)
@Controller('contracts/smoke-scenarios')
export class SmokeScenariosController {
  constructor(private readonly smokeScenarios: SmokeScenariosService) {}

  @Post('validate')
  @HttpCode(HttpStatus.OK)
  @RequireScopes('admin')
  @ApiOperation({
    summary: 'Validate a contract smoke-scenarios artifact',
    description:
      'Consumes the canonical quickex-smoke-scenarios-v1 artifact and verifies it ' +
      'conforms to the schema. Returns field-level errors when invalid and the ' +
      'normalized artifact when valid.',
  })
  @ApiResponse({ status: 200, type: SmokeScenariosValidationResultDto })
  @ApiResponse({ status: 400, description: 'Artifact does not conform to the schema' })
  validate(
    @Body() dto: ConsumeSmokeScenariosDto,
  ): SmokeScenariosValidationResultDto {
    return this.smokeScenarios.validate(dto.artifact);
  }
}
