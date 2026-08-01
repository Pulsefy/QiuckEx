import { Controller, Get, Query, UsePipes, ValidationPipe } from '@nestjs/common';
import { ApiOperation, ApiTags } from '@nestjs/swagger';
import { DashboardFeedService } from './dashboard-feed.service';
import { GetFeedQueryDto } from './dto/get-feed.dto';
import type { FeedResponse } from './dashboard-feed.types';

@ApiTags('Dashboard Feed')
@Controller('dashboard-feed')
@UsePipes(new ValidationPipe({ transform: true, whitelist: true }))
export class DashboardFeedController {
  constructor(private readonly feedService: DashboardFeedService) {}

  @Get()
  @ApiOperation({
    summary: 'Get activity feed',
    description:
      'Returns a unified, cursor-paginated activity feed aggregating payments, ' +
      'refunds, webhook deliveries, in-app notifications, contract events, and ' +
      'username actions for the given address. Feed ordering is deterministic ' +
      'across repeated requests (timestamp DESC, id DESC).',
  })
  async getFeed(@Query() query: GetFeedQueryDto): Promise<FeedResponse> {
    return this.feedService.getFeed(query);
  }
}
