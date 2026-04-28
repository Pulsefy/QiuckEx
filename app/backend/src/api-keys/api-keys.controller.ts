import {
  Body,
  Controller,
  Delete,
  Get,
  Param,
  ParseUUIDPipe,
  Post,
  Query,
} from '@nestjs/common';
import { ApiOperation, ApiQuery, ApiResponse, ApiTags } from '@nestjs/swagger';
import { ApiKeysService } from './api-keys.service';
import { CreateApiKeyDto } from './dto/create-api-key.dto';
import { CursorPaginationQueryDto } from '../dto/pagination/pagination.dto';

@ApiTags('api-keys')
@Controller('api-keys')
export class ApiKeysController {
  constructor(private readonly service: ApiKeysService) {}

  /**
   * POST /api-keys
   * Creates a new API key. The raw key is returned ONCE in the response.
   */
  @Post()
  create(@Body() dto: CreateApiKeyDto) {
    return this.service.create(dto);
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
    @Query('owner_id') ownerId?: string,
    @Query() pagination?: CursorPaginationQueryDto,
  ) {
    return this.service.listPaginated(ownerId, pagination?.cursor, pagination?.limit);
  }

  /**
   * GET /api-keys/usage
   * Returns aggregated usage/quota stats.
   */
  @Get('usage')
  usage(@Query('owner_id') ownerId?: string) {
    return this.service.getUsage(ownerId);
  }

  /**
   * DELETE /api-keys/:id
   * Revokes (soft-deletes) a key.
   */
  @Delete(':id')
  revoke(@Param('id', ParseUUIDPipe) id: string) {
    return this.service.revoke(id);
  }

  /**
   * POST /api-keys/:id/rotate
   * Invalidates the current key and issues a new one.
   */
  @Post(':id/rotate')
  rotate(@Param('id', ParseUUIDPipe) id: string) {
    return this.service.rotate(id);
  }
}
