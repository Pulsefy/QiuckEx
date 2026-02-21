import { Injectable, Logger, HttpException, HttpStatus } from '@nestjs/common';
import { Horizon } from 'stellar-sdk';
import { LRUCache } from 'lru-cache';
import { AppConfigService } from '../config/app-config.service';
import { TransactionItemDto, TransactionResponseDto } from './dto/transaction.dto';

@Injectable()
export class HorizonService {
    private readonly logger = new Logger(HorizonService.name);
    private readonly server: Horizon.Server;
    private readonly cache: LRUCache<string, TransactionResponseDto>;
    private readonly backoffCache: LRUCache<string, { attempts: number; lastAttempt: number }>;
    private readonly maxRetries = 3;
    private readonly baseDelay = 1000; // 1 second
    private readonly maxDelay = 30000; // 30 seconds

    constructor(private readonly configService: AppConfigService) {
        const horizonUrl = this.configService.network === 'mainnet'
            ? 'https://horizon.stellar.org'
            : 'https://horizon-testnet.stellar.org';

        this.server = new Horizon.Server(horizonUrl);

        // Main cache for transaction responses
        this.cache = new LRUCache({
            max: this.configService.cacheMaxItems || 500,
            ttl: this.configService.cacheTtlMs || 60000, // 60 seconds default
            updateAgeOnGet: true, // Refresh TTL on access
        });

        // Backoff tracking cache
        this.backoffCache = new LRUCache({
            max: 1000,
            ttl: 300000, // 5 minutes
        });

        this.logger.log(`HorizonService initialized for ${this.configService.network} network`);
        this.logger.log(`Cache configured: max=${this.cache.max}, ttl=${this.cache.ttl}ms`);
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
        
        // Check cache first
        const cached = this.cache.get(cacheKey);
        if (cached) {
            this.logger.debug(`Cache hit for key: ${cacheKey}`);
            return cached;
        }

        // Check backoff status
        const backoffInfo = this.backoffCache.get(cacheKey);
        if (backoffInfo) {
            const timeSinceLastAttempt = Date.now() - backoffInfo.lastAttempt;
            const delay = this.calculateDelay(backoffInfo.attempts);
            
            if (timeSinceLastAttempt < delay) {
                this.logger.warn(`Backoff in effect for key: ${cacheKey}. Delay: ${delay}ms`);
                throw new HttpException(
                    `Service temporarily unavailable due to rate limiting. Please try again in ${(delay - timeSinceLastAttempt) / 1000} seconds.`,
                    HttpStatus.SERVICE_UNAVAILABLE
                );
            }
        }

        try {
            const result = await this.fetchFromHorizonWithRetry(accountId, asset, limit, cursor, cacheKey);
            
            // Reset backoff on success
            this.backoffCache.delete(cacheKey);
            
            // Cache the result
            this.cache.set(cacheKey, result);
            this.logger.debug(`Cached result for key: ${cacheKey}`);
            
            return result;
        } catch (error) {
            // Update backoff tracking
            this.updateBackoff(cacheKey);
            this.handleHorizonError(error);
        }
    }

    private async fetchFromHorizonWithRetry(
        accountId: string,
        asset: string | undefined,
        limit: number,
        cursor: string | undefined,
        // eslint-disable-next-line @typescript-eslint/no-unused-vars
        _cacheKey: string
    ): Promise<TransactionResponseDto> {
        let lastError: unknown;
        
        for (let attempt = 1; attempt <= this.maxRetries; attempt++) {
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
                const payments = records.filter(record =>
                    record.type === 'payment' ||
                    record.type === 'path_payment_strict_receive' ||
                    record.type === 'path_payment_strict_send'
                ) as (Horizon.ServerApi.PaymentOperationRecord | Horizon.ServerApi.PathPaymentOperationRecord | Horizon.ServerApi.PathPaymentStrictSendOperationRecord)[];

                const items: TransactionItemDto[] = await Promise.all(
                    payments.map(async (payment) => {
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

                // Apply asset filtering
                let filteredItems = items;
                if (asset) {
                    filteredItems = items.filter(item => item.asset === asset);
                }

                return {
                    items: filteredItems,
                    nextCursor: records.length > 0 ? records[records.length - 1].paging_token : undefined,
                };

            } catch (error) {
                lastError = error;
                const err = error as { response?: { status: number } };
                
                // Don't retry on client errors or non-retryable server errors
                if (err.response?.status && err.response.status < 500 && err.response.status !== 429) {
                    throw error;
                }
                
                // Don't retry on the last attempt
                if (attempt === this.maxRetries) {
                    throw error;
                }
                
                // Calculate delay with exponential backoff and jitter
                const delay = this.calculateDelay(attempt);
                this.logger.warn(`Horizon request failed (attempt ${attempt}/${this.maxRetries}), retrying in ${delay}ms: ${err.response?.status || 'Unknown error'}`);
                
                await this.sleep(delay);
            }
        }
        
        throw lastError;
    }

    private calculateDelay(attempt: number): number {
        // Exponential backoff with full jitter
        const exponentialDelay = Math.min(
            this.baseDelay * Math.pow(2, attempt - 1),
            this.maxDelay
        );
        return Math.floor(exponentialDelay + Math.random() * exponentialDelay);
    }

    private updateBackoff(cacheKey: string): void {
        const existing = this.backoffCache.get(cacheKey);
        const attempts = existing ? Math.min(existing.attempts + 1, this.maxRetries) : 1;
        
        this.backoffCache.set(cacheKey, {
            attempts,
            lastAttempt: Date.now()
        });
    }

    private sleep(ms: number): Promise<void> {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    private handleHorizonError(error: unknown): never {
        const err = error as { response?: { status: number; data: unknown }; message?: string };
        
        if (err.response) {
            const status = err.response.status;
            
            switch (status) {
                case 429:
                    this.logger.error('Horizon rate limit exceeded');
                    throw new HttpException(
                        'Horizon service rate limit exceeded. Please try again later.',
                        HttpStatus.SERVICE_UNAVAILABLE,
                    );
                
                case 502:
                case 503:
                case 504:
                    this.logger.error(`Horizon service unavailable: ${status}`);
                    throw new HttpException(
                        'Horizon service temporarily unavailable. Please try again later.',
                        HttpStatus.SERVICE_UNAVAILABLE,
                    );
                
                case 500:
                    this.logger.error(`Horizon internal server error: ${status}`);
                    throw new HttpException(
                        'Horizon service encountered an internal error.',
                        HttpStatus.BAD_GATEWAY,
                    );
                
                default:
                    this.logger.error(`Horizon client error: ${status} - ${JSON.stringify(err.response.data)}`);
                    throw new HttpException(
                        'Invalid request to Horizon service',
                        HttpStatus.BAD_REQUEST,
                    );
            }
        }

        this.logger.error(`Unexpected error fetching from Horizon: ${err.message || String(error)}`);
        throw new HttpException(
            'Internal server error while fetching transactions',
            HttpStatus.INTERNAL_SERVER_ERROR,
        );
    }

    /**
     * Get cache statistics for monitoring
     */
    getCacheStats() {
        return {
            entries: this.cache.size,
            maxEntries: this.cache.max,
            ttl: this.cache.ttl,
            backoffEntries: this.backoffCache.size,
        };
    }

    /**
     * Clear all cached data (useful for testing)
     */
    clearCache(): void {
        this.cache.clear();
        this.backoffCache.clear();
        this.logger.debug('Cache cleared');
    }
}
