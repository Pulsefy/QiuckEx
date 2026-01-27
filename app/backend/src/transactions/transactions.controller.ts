import { Controller, Get, Query, UsePipes, ValidationPipe } from '@nestjs/common';
import { ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';
import { GetTransactionsQueryDto, TransactionResponseDto } from './dto/transaction.dto';
import { HorizonService } from './horizon.service';

@ApiTags('transactions')
@Controller('transactions')
export class TransactionsController {
    constructor(private readonly horizonService: HorizonService) { }

    @Get()
    @ApiOperation({
        summary: 'Fetch recent Stellar transactions (payments)',
        description:
            'Fetches recent payment operations for a given account. ' +
            'Results are cached for 60 seconds and support pagination via cursor.',
    })
    @ApiResponse({
        status: 200,
        description: 'List of normalized payment items',
        type: TransactionResponseDto,
    })
    @ApiResponse({
        status: 400,
        description: 'Invalid query parameters',
    })
    @ApiResponse({
        status: 503,
        description: 'Horizon service rate limit exceeded or unavailable',
    })
    @UsePipes(new ValidationPipe({ transform: true }))
    async getTransactions(
        @Query() query: GetTransactionsQueryDto,
    ): Promise<TransactionResponseDto> {
        const { accountId, asset, limit, cursor } = query;
        return this.horizonService.getPayments(accountId, asset, limit, cursor);
    }
}
