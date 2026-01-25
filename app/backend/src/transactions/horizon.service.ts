import { Injectable, Logger, HttpException, HttpStatus } from '@nestjs/common';
import { Horizon, Server } from 'stellar-sdk';
import { LRUCache } from 'lru-cache';
import { AppConfigService } from '../config/app-config.service';
import { TransactionItemDto, TransactionResponseDto } from './dto/transaction.dto';

@Injectable()
export class HorizonService {
    private readonly logger = new Logger(HorizonService.name);
    private readonly server: Server;
    private readonly cache: LRUCache<string, TransactionResponseDto>;

    constructor(private readonly configService: AppConfigService) {
        const horizonUrl = this.configService.network === 'mainnet'
            ? 'https://horizon.stellar.org'
            : 'https://horizon-testnet.stellar.org';

        this.server = new Server(horizonUrl);

        this.cache = new LRUCache({
            max: 500, // Maximum number of items in cache
            ttl: 1000 * 60, // Default TTL 60 seconds (configurable via env in high-perf apps)
        });

        this.logger.log(`HorizonService initialized for ${this.configService.network} network`);
    }

    /**
     * Fetches payments (operations) for a given account.
     * Uses operations endpoint to reliably extract amount and asset.
     */
    async getPayments(
        accountId: string,
        asset?: string,
        limit: number = 20,
        cursor?: string,
    ): Promise<TransactionResponseDto> {
        const cacheKey = `${this.configService.network}:${accountId}:${asset ?? 'any'}:${limit}:${cursor ?? 'start'}`;

        const cached = this.cache.get(cacheKey);
        if (cached) {
            this.logger.debug(`Cache hit for key: ${cacheKey}`);
            return cached;
        }

        try {
            let query = this.server.operations()
                .forAccount(accountId)
                .order('desc')
                .limit(limit);

            if (cursor) {
                query = query.cursor(cursor);
            }

            const response = await query.call();
            const records = response.records;

            // Filter and normalize payment operations
            // We filter for payment and path_payment_* types
            const payments = records.filter(record =>
                record.type === 'payment' ||
                record.type === 'path_payment_strict_receive' ||
                record.type === 'path_payment_strict_send'
            ) as (Horizon.ServerApi.PaymentOperationRecord | Horizon.ServerApi.PathPaymentStrictReceiveOperationRecord | Horizon.ServerApi.PathPaymentStrictSendOperationRecord)[];

            const items: TransactionItemDto[] = await Promise.all(
                payments.map(async (payment) => {
                    // Fetch memo from the parent transaction
                    // Note: In a high-traffic production app, we might want to batch these or cache transaction headers
                    let memo: string | undefined;
                    try {
                        const tx = await payment.transaction();
                        memo = tx.memo;
                    } catch (e) {
                        this.logger.warn(`Failed to fetch memo for transaction ${payment.transaction_hash}`);
                    }

                    let assetString = 'XLM';
                    if ('asset_type' in payment && payment.asset_type !== 'native') {
                        assetString = `${payment.asset_code}:${payment.asset_issuer}`;
                    }

                    return {
                        amount: payment.amount,
                        asset: assetString,
                        memo: memo,
                        timestamp: payment.created_at,
                        txHash: payment.transaction_hash,
                        pagingToken: payment.paging_token,
                    };
                })
            );

            // If an asset filter is provided, filter the results
            // Horizon's operations endpoint doesn't support asset filtering directly for account operations
            let filteredItems = items;
            if (asset) {
                filteredItems = items.filter(item => item.asset === asset);
            }

            const result: TransactionResponseDto = {
                items: filteredItems,
                nextCursor: records.length > 0 ? records[records.length - 1].paging_token : undefined,
            };

            this.cache.set(cacheKey, result);
            return result;

        } catch (error) {
            this.handleHorizonError(error);
        }
    }

    private handleHorizonError(error: any): never {
        if (error.response) {
            const status = error.response.status;
            if (status === 429) {
                this.logger.error('Horizon rate limit exceeded');
                throw new HttpException(
                    'Horizon service rate limit exceeded. Please try again later.',
                    HttpStatus.SERVICE_UNAVAILABLE,
                );
            }

            this.logger.error(`Horizon error: ${status} - ${JSON.stringify(error.response.data)}`);
            throw new HttpException(
                'Error fetching data from Horizon',
                status >= 500 ? HttpStatus.BAD_GATEWAY : HttpStatus.BAD_REQUEST,
            );
        }

        this.logger.error(`Unexpected error fetching from Horizon: ${error.message}`);
        throw new HttpException(
            'Internal server error while fetching transactions',
            HttpStatus.INTERNAL_SERVER_ERROR,
        );
    }
}
