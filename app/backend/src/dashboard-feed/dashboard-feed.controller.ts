import { Controller, Get, Query, UsePipes, ValidationPipe } from '@nestjs/common';
import { ApiOkResponse, ApiOperation, ApiTags } from '@nestjs/swagger';
import { DashboardFeedService } from './dashboard-feed.service';
import { GetFeedQueryDto } from './dto/get-feed.dto';
import { FeedResponseDto } from './dto/dashboard-feed-response.dto';
import type { FeedResponse } from './dashboard-feed.types';
import { RateLimitTier } from '../auth/decorators/rate-limit-group.decorator';
import {
  RequiresIndexerLagCheck,
  IndexerLagPolicy,
} from '../indexer-lag/requires-indexer-lag-check.decorator';

@ApiTags('Dashboard Feed')
@Controller('dashboard-feed')
@UsePipes(new ValidationPipe({ transform: true, whitelist: true }))
export class DashboardFeedController {
  constructor(private readonly feedService: DashboardFeedService) {}

  @Get()
  @RateLimitTier("search")
  // The feed is an activity view, not an authoritative ledger read: a feed
  // that is a few ledgers behind is still useful (and is already ordered
  // timestamp DESC), so it is served with an explicit staleness header rather
  // than a 503. See docs/INDEXER-LAG-GUARD-ROUTES.md.
  @RequiresIndexerLagCheck(IndexerLagPolicy.STALE_HEADER)
  @ApiOperation({
    summary: 'Get activity feed',
    description:
      'Returns a unified, cursor-paginated activity feed aggregating payments, ' +
      'refunds, webhook deliveries, in-app notifications, contract events, and ' +
      'username actions for the given address. Feed ordering is deterministic ' +
      'across repeated requests (timestamp DESC, id DESC).',
  })
  @ApiOkResponse({
    description: 'Cursor-paginated activity feed',
    type: FeedResponseDto,
  })
  async getFeed(@Query() query: GetFeedQueryDto): Promise<FeedResponse> {
    return this.feedService.getFeed(query);
  }
}

