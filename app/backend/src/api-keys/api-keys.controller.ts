import {
  Body,
  Controller,
  Delete,
  Get,
  Param,
  ParseUUIDPipe,
  Post,
  Query,
  Req,
} from '@nestjs/common';
import { ApiOperation, ApiQuery, ApiResponse, ApiTags } from '@nestjs/swagger';
import { Request } from 'express';
import { ApiKeysService } from './api-keys.service';
import { CreateApiKeyDto } from './dto/create-api-key.dto';
import { CursorPaginationQueryDto } from '../dto/pagination/pagination.dto';
import { RequireOrgRole } from '../auth/decorators/require-org-role.decorator';

@ApiTags('api-keys')
@Controller('api-keys')
export class ApiKeysController {
  constructor(private readonly service: ApiKeysService) {}

  /**
   * POST /api-keys
   * Creates a new API key. The raw key is returned ONCE in the response.
   */
  @Post()
  @RequireOrgRole('admin')
  create(@Body() dto: CreateApiKeyDto, @Req() req: Request) {
    return this.service.create({
      ...dto,
      organization_id: dto.organization_id ?? req.organizationContext?.organizationId,
    });
  }

  /**
   * GET /api-keys
   * Lists all active keys (masked) with cursor-based pagination. Optionally filter by owner_id.
   */
  @Get()
  @ApiOperation({ summary: 'List API keys with cursor-based pagination' })
  @ApiQuery({ name: 'owner_id', required: false })
  @ApiQuery({ name: 'cursor', required: false, description: 'Opaque pagination cursor' })
  @ApiQuery({ name: 'limit', required: false, type: Number, description: 'Items per page (1-100)' })
  @ApiResponse({ status: 200, description: 'Paginated list of API keys' })
  list(
    @Req() req: Request,
    @Query('owner_id') ownerId?: string,
    @Query() pagination?: CursorPaginationQueryDto,
  ) {
    return this.service.listPaginated(
      ownerId,
      req.organizationContext?.organizationId,
      pagination?.cursor,
      pagination?.limit,
    );
  }

  /**
   * GET /api-keys/usage
   * Returns aggregated usage/quota stats.
   */
  @Get('usage')
  usage(@Req() req: Request, @Query('owner_id') ownerId?: string) {
    return this.service.getUsage(ownerId, req.organizationContext?.organizationId);
  }

  /**
   * DELETE /api-keys/:id
   * Revokes (soft-deletes) a key.
   */
  @Delete(':id')
  @RequireOrgRole('admin')
  revoke(@Param('id', ParseUUIDPipe) id: string) {
    return this.service.revoke(id);
  }

  /**
   * POST /api-keys/:id/rotate
   * Invalidates the current key and issues a new one.
   */
  @Post(':id/rotate')
  @RequireOrgRole('admin')
  rotate(@Param('id', ParseUUIDPipe) id: string) {
    return this.service.rotate(id);
  }
}
