import { Controller, Get, Query } from '@nestjs/common';
import {
  ApiOperation,
  ApiResponse,
  ApiTags,
  ApiQuery,
} from '@nestjs/swagger';

import { DashboardService } from './dashboard.service';
import { FeedQueryDto } from './dto/feed-query.dto';
import { FeedResponseDto } from './dto/feed-response.dto';

@ApiTags('dashboard')
@Controller('v1/dashboard')
export class DashboardController {
  constructor(private readonly dashboardService: DashboardService) {}

  /**
   * GET /v1/dashboard/feed
   *
   * Returns a unified, cursor-paginated activity feed by merging
   * payments, refunds, notifications, contract actions, username claims,
   * and webhook deliveries into a single chronologically-sorted response.
   */
  @Get('feed')
  @ApiOperation({
    summary: 'Get dashboard activity feed',
    description:
      'Returns a unified, cursor-paginated feed of activity items across ' +
      'payments, refunds, in-app notifications, contract actions, username ' +
      'claims, and webhook deliveries. Results are returned in reverse ' +
      'chronological order with deterministic tie-breaking. Filter by type ' +
      'using the `types` parameter (comma-separated).',
  })
  @ApiQuery({
    name: 'publicKey',
    description: 'Stellar public key to scope the feed to a user',
    required: false,
    example: 'GABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234',
  })
  @ApiResponse({
    status: 200,
    description: 'Feed items with pagination metadata',
    type: FeedResponseDto,
  })
  @ApiResponse({
    status: 400,
    description: 'Invalid query parameters',
  })
  async getFeed(
    @Query() query: FeedQueryDto,
  ): Promise<FeedResponseDto> {
    const result = await this.dashboardService.getFeed({
      publicKey: query.publicKey,
      types: query.types,
      cursor: query.cursor,
      limit: query.limit,
    });

    return {
      items: result.items,
      pagination: result.pagination,
    };
  }
}
