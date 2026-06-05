import {
  Controller,
  Get,
  Post,
  Body,
  HttpCode,
  HttpStatus,
  BadRequestException,
  UseGuards,
} from '@nestjs/common';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiHeader,
  ApiBody,
} from '@nestjs/swagger';
import { ContractCompatibilityService } from './contract-compatibility.service';
import {
  ClientContractRequirements,
  ContractCompatibilityMetadata,
  ContractCompatibilityCheckResponse,
} from './dto/contract-compatibility.dto';
import { ApiKeyGuard } from '../auth/guards/api-key.guard';

@ApiTags('contracts')
@ApiHeader({
  name: 'X-API-Key',
  description: 'Optional API key for higher rate limits',
  required: false,
})
@UseGuards(ApiKeyGuard)
@Controller('contracts')
export class ContractCompatibilityController {
  constructor(
    private readonly compatibilityService: ContractCompatibilityService,
  ) {}

  @Post('compatibility/check')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Check contract compatibility',
    description:
      'Validates whether the client\'s contract version requirements are compatible with the currently deployed contracts. ' +
      'Clients should call this endpoint before performing critical operations to ensure compatibility.',
  })
  @ApiBody({
    type: ClientContractRequirements,
    description: 'Client\'s contract version requirements',
    examples: {
      default: {
        value: {
          requirements: [
            { name: 'quickex', minVersion: 1 },
          ],
          clientVersion: '1.0.0',
        },
      },
    },
  })
  @ApiResponse({
    status: 200,
    type: ContractCompatibilityCheckResponse,
    description: 'Compatibility check completed',
  })
  @ApiResponse({
    status: 400,
    description: 'Invalid contract requirements provided',
  })
  async checkCompatibility(
    @Body() requirements: ClientContractRequirements,
  ): Promise<ContractCompatibilityCheckResponse> {
    if (!requirements.requirements || requirements.requirements.length === 0) {
      throw new BadRequestException({
        code: 'INVALID_CONTRACT_REQUIREMENTS',
        message: 'At least one contract requirement must be specified',
      });
    }

    const compatibility = await this.compatibilityService.checkClientCompatibility(requirements);

    const recommendation = compatibility.compatible
      ? { message: 'All contracts are compatible', action: 'proceed' as const }
      : {
          message: 'Client upgrade required to continue',
          action: 'upgrade_required' as const,
        };

    return { compatibility, recommendation };
  }

  @Get('compatibility/requirements')
  @ApiOperation({
    summary: 'Get server contract requirements',
    description:
      'Returns the contract version requirements for all endpoints. ' +
      'Useful for clients to determine what versions they need to support.',
  })
  @ApiResponse({
    status: 200,
    description: 'List of endpoint contract requirements',
  })
  getEndpointRequirements() {
    return {
      requirements: this.compatibilityService.getAllEndpointRequirements(),
    };
  }

  @Post('compatibility/validate')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Validate request compatibility',
    description:
      'Validates whether a request to a specific endpoint is compatible with contract requirements. ' +
      'This endpoint simulates the validation that would occur for an actual request.',
  })
  @ApiBody({
    schema: {
      type: 'object',
      required: ['endpoint', 'method'],
      properties: {
        endpoint: {
          type: 'string',
          example: 'links/metadata',
          description: 'The endpoint path to validate',
        },
        method: {
          type: 'string',
          enum: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'],
          example: 'POST',
          description: 'The HTTP method',
        },
        requirements: {
          type: 'object',
          description: 'Optional client contract requirements',
        },
      },
    },
  })
  @ApiResponse({
    status: 200,
    description: 'Validation completed',
  })
  async validateEndpoint(
    @Body() body: {
      endpoint: string;
      method: string;
      requirements?: ClientContractRequirements;
    },
  ): Promise<{
    compatible: boolean;
    metadata?: ContractCompatibilityMetadata;
    recommendation: { message: string; action: string };
  }> {
    const { endpoint, method, requirements } = body;

    const result = await this.compatibilityService.validateRequestCompatibility(
      endpoint,
      method,
      requirements,
    );

    const recommendation = result.compatible
      ? { message: 'Endpoint is compatible', action: 'proceed' }
      : { message: 'Endpoint requires contract upgrade', action: 'upgrade_required' };

    return {
      ...result,
      recommendation,
    };
  }
}