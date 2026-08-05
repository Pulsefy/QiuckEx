import {
  Controller,
  Get,
  Headers,
  Req,
  Res,
} from '@nestjs/common';
import { ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';
import { Request, Response } from 'express';

import { RuntimeConfigResponseDto } from './dto/runtime-config.dto';
import { RuntimeConfigService } from './runtime-config.service';

@ApiTags('runtime-config')
@Controller('v1/runtime-config')
export class RuntimeConfigController {
  constructor(private readonly runtimeConfigService: RuntimeConfigService) {}

  @Get()
  @ApiOperation({
    summary: 'Public runtime configuration bootstrap',
    description:
      'Returns environment-aware API, network, and contract metadata for web and mobile clients. ' +
      'Set X-Preview-Scope header to include preview environment metadata. ' +
      'Supports ETag-based caching via If-None-Match header.',
  })
  @ApiResponse({
    status: 200,
    type: RuntimeConfigResponseDto,
    description: 'Runtime configuration for the active environment',
  })
  @ApiResponse({
    status: 304,
    description: 'Not Modified — config unchanged since provided ETag',
  })
  async getConfig(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
    @Headers('x-preview-scope') previewScope?: string,
  ): Promise<RuntimeConfigResponseDto | void> {
    const config = await this.runtimeConfigService.getConfig(previewScope);
    this.runtimeConfigService.validateConfig(config);

    res.setHeader('Cache-Control', 'public, max-age=0, must-revalidate');
    res.setHeader('ETag', config.etag);

    const clientEtag = req.headers['if-none-match'];
    if (clientEtag && clientEtag === config.etag) {
      res.status(304);
      return;
    }

    return config;
  }
}
