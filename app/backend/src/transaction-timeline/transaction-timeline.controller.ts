import {
  Controller,
  Get,
  Query,
  UsePipes,
  ValidationPipe,
} from '@nestjs/common';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiQuery,
} from '@nestjs/swagger';

import { TransactionTimelineService } from './transaction-timeline.service';
import { GetTimelineQueryDto } from './dto/get-timeline.dto';
import type { TimelineResponse } from './transaction-timeline.types';

@ApiTags('transaction-timeline')
@Controller('transaction-timeline')
export class TransactionTimelineController {
  constructor(private readonly timelineService: TransactionTimelineService) {}

  /**
   * GET /transaction-timeline
   *
   * Returns an ordered, deduplicated list of timeline events for a given
   * Stellar transaction hash. Events span payments, refunds, webhook
   * delivery logs, and contract change notifications.
   *
   * Partial data is returned when one or more sources are unavailable so
   * that frontend/mobile views always receive useful context.
   */
  @Get()
  @UsePipes(new ValidationPipe({ transform: true, whitelist: true }))
  @ApiOperation({
    summary: 'Get aggregated transaction timeline',
    description:
      'Aggregates payment, refund, webhook, and contract event history ' +
      'into a single ordered timeline for the given transaction hash. ' +
      'When individual data sources fail the response is still returned ' +
      'with isPartial=true and a failedSources list.',
  })
  @ApiQuery({ name: 'txHash', required: true, description: 'Stellar transaction hash' })
  @ApiQuery({ name: 'address', required: false, description: 'Stellar public key (scopes webhook lookups)' })
  @ApiQuery({
    name: 'kind',
    required: false,
    enum: ['payment', 'refund', 'webhook_delivery', 'contract_event'],
    description: 'Filter to a single event kind',
  })
  @ApiQuery({ name: 'limit', required: false, description: 'Max items (1–200, default 50)' })
  @ApiResponse({
    status: 200,
    description: 'Ordered timeline (may be partial when some sources fail)',
    schema: {
      example: {
        txHash: 'abc123...',
        items: [
          {
            id: 'pay_abc123_0',
            kind: 'payment',
            timestamp: '2024-01-01T00:00:00Z',
            title: 'Payment Success',
            description: '10.00 USDC from GABC…1234 to GDEF…5678',
            status: 'success',
            correlationId: 'abc123...',
            receiptRef: { receiptId: 'rcpt_abc123_0', txHash: 'abc123', url: '/receipts/abc123' },
            paymentDetail: {
              txHash: 'abc123',
              amount: '10.00',
              asset: 'USDC:GABCD...',
              sender: 'GABC...',
              receiver: 'GDEF...',
              memo: null,
              ledger: null,
              pagingToken: null,
            },
            refundDetail: null,
            webhookDetail: null,
            contractDetail: null,
          },
        ],
        total: 1,
        isPartial: false,
        failedSources: [],
      },
    },
  })
  @ApiResponse({ status: 400, description: 'Invalid query parameters' })
  async getTimeline(
    @Query() query: GetTimelineQueryDto,
  ): Promise<TimelineResponse> {
    return this.timelineService.getTimeline(query);
  }
}
