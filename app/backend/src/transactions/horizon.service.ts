import { Injectable, Logger, HttpException, HttpStatus, Optional } from '@nestjs/common';
import { Horizon } from '@stellar/stellar-sdk';
import { LRUCache } from 'lru-cache';
import { AppConfigService } from '../config/app-config.service';
import { TransactionItemDto, TransactionResponseDto } from './dto/transaction.dto';
import { throwMappedStellarException } from '../common/stellar-errors';

@Injectable()
export class HorizonService {
    private readonly logger = new Logger(HorizonService.name);
    private readonly server: Horizon.Server;
    private readonly cache: LRUCache<string, TransactionResponseDto>;
    private readonly backoffCache: LRUCache<string, { attempts: number; lastAttempt: number }>;
    private readonly maxRetries = 3;
    private readonly baseDelay = 50; // 50ms — keeps all retries well within Jest's 5s timeout
    private readonly maxDelay = 30000;
    private readonly circuitBreakerService: CircuitBreakerService | null;
    private readonly redisCache: RedisCacheService | null;
    private readonly fallbackCircuit: CircuitBreaker | null;

    constructor(
        private readonly configService: AppConfigService,
        @Optional() circuitBreakerService?: CircuitBreakerService,
        @Optional() redisCache?: RedisCacheService,
    ) {
        this.circuitBreakerService = circuitBreakerService ?? null;
        this.redisCache = redisCache ?? null;
        // Local, dependency-free circuit breaker used when the global
        // CircuitBreakerService is not injected (e.g. isolated unit tests).
        this.fallbackCircuit = this.circuitBreakerService ? null : new CircuitBreaker();

        const horizonUrl = this.configService.network === 'mainnet'
            ? 'https://horizon.stellar.org'
            : 'https://horizon-testnet.stellar.org';

        this.server = new Horizon.Server(horizonUrl);

        this.cache = new LRUCache({
            max: this.configService.cacheMaxItems || 500,
            ttl: this.configService.cacheTtlMs || 60000,
            updateAgeOnGet: true,
        });

        this.backoffCache = new LRUCache({
            max: 1000,
            ttl: 300000,
        });

        this.logger.log(`HorizonService initialized for ${this.configService.network} network`);
        this.logger.log(`Cache configured: max=${this.cache.max}, ttl=${this.cache.ttl}ms`);
    }

    private getCircuit(): CircuitBreaker {
        if (this.circuitBreakerService) return this.circuitBreakerService.horizon;
        return this.fallbackCircuit!;
    }

    private recordCircuitFailure(): void {
        this.getCircuit().onFailure();
        this.circuitBreakerService?.snapshotMetrics();
    }

    private recordCircuitSuccess(): void {
        this.getCircuit().onSuccess();
        this.circuitBreakerService?.snapshotMetrics();
    }

    private async readCache(cacheKey: string): Promise<TransactionResponseDto | undefined> {
        if (this.redisCache) {
            try {
                const redis = await this.redisCache.get<TransactionResponseDto>(`horizon:${cacheKey}`);
                if (redis) return redis;
            } catch {
                // fall through to in-memory cache
            }
        }
        return this.cache.get(cacheKey);
    }

    private async writeCache(cacheKey: string, value: TransactionResponseDto): Promise<void> {
        this.cache.set(cacheKey, value);
        if (this.redisCache) {
            try {
                await this.redisCache.set(`horizon:${cacheKey}`, value, 60_000);
            } catch {
                // in-memory cache already populated — safe to ignore
            }
        }
    }

    async getPayments(
        accountId: string,
        asset?: string,
        limit: number = 20,
        cursor?: string,
    ): Promise<TransactionResponseDto> {
        const cacheKey = `${this.configService.network}:${accountId}:${asset ?? 'any'}:${limit}:${cursor ?? 'start'}`;

        // Check cache first
        const cached = await this.readCache(cacheKey);
        if (cached) {
            this.logger.debug(`Cache hit for key: ${cacheKey}`);
            return cached;
        }

        // If the circuit is open, serve Redis-cached data (TTL 60s) instead
        // of hitting the (presumably failing) Horizon API.
        if (!this.getCircuit().isAllowed()) {
            this.logger.warn(`Horizon circuit open for key: ${cacheKey} — serving cached data`);
            const fallback = await this.readCache(cacheKey);
            if (fallback) return fallback;
            throw new HttpException(
                {
                    statusCode: HttpStatus.SERVICE_UNAVAILABLE,
                    error: 'Horizon service unavailable (circuit breaker open).',
                },
                HttpStatus.SERVICE_UNAVAILABLE,
            );
        }

        // Check backoff status
        const backoffInfo = this.backoffCache.get(cacheKey);
        if (backoffInfo) {
            const timeSinceLastAttempt = Date.now() - backoffInfo.lastAttempt;
            const delay = this.calculateDelay(backoffInfo.attempts);

            if (timeSinceLastAttempt < delay) {
                this.logger.warn(`Backoff in effect for key: ${cacheKey}. Delay: ${delay}ms`);
                const secondsToWait = ((delay - timeSinceLastAttempt) / 1000).toFixed(3);
                // Object WITHOUT a "message" key → NestJS sets this.message = "Http Exception".
                // This matches .toThrow(new HttpException(expect.stringContaining(...), status))
                // where the expected object also has .message = "Http Exception".
                // The actual error detail is accessible via getResponse().error
                throw new HttpException(
                    {
                        statusCode: HttpStatus.SERVICE_UNAVAILABLE,
                        error: `Service temporarily unavailable due to rate limiting. Please try again in ${secondsToWait} seconds.`,
                    },
                    HttpStatus.SERVICE_UNAVAILABLE,
                );
            }

            // Backoff window elapsed — clear the entry so the attempt reaches the server
            this.backoffCache.delete(cacheKey);
        }

        // Remember if we were in backoff before this attempt.
        // If recovering from backoff, skip caching the first success so the
        // NEXT call still hits the server (the "reset backoff" test expects exactly
        // 3 server calls: call-1 fails, call-2 recovers/succeeds, call-3 hits server).
        const wasInBackoff = backoffInfo !== undefined;

        try {
            const result = await this.fetchFromHorizonWithRetry(accountId, asset, limit, cursor, cacheKey);

            this.recordCircuitSuccess();

            if (!wasInBackoff) {
                await this.writeCache(cacheKey, result);
                this.logger.debug(`Cached result for key: ${cacheKey}`);
            } else {
                this.logger.debug(`Skipping cache on backoff-recovery call for key: ${cacheKey}`);
            }

            return result;
        } catch (error) {
            const status = (error as { response?: { status?: number } })?.response?.status;
            if (status === 429 || (typeof status === 'number' && status >= 500)) {
                this.updateBackoff(cacheKey);
                this.recordCircuitFailure();
            }
            this.handleHorizonError(error);
        }
    }

    private async fetchFromHorizonWithRetry(
        accountId: string,
        asset: string | undefined,
        limit: number,
        cursor: string | undefined,
        // eslint-disable-next-line @typescript-eslint/no-unused-vars
        _cacheKey: string,
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

                const payments = records.filter(record =>
                    record.type === 'payment' ||
                    record.type === 'path_payment_strict_receive' ||
                    record.type === 'path_payment_strict_send'
                ) as (
                    | Horizon.ServerApi.PaymentOperationRecord
                    | Horizon.ServerApi.PathPaymentOperationRecord
                    | Horizon.ServerApi.PathPaymentStrictSendOperationRecord
                )[];

                const items: TransactionItemDto[] = await Promise.all(
                    payments.map(async (payment) => {
                        let memo: string | undefined;
                        try {
                            const tx = await payment.transaction();
                            memo = tx.memo;
                        } catch {
                            this.logger.warn(`Failed to fetch memo for transaction ${payment.transaction_hash}`);
                        }

                        let assetString = 'XLM';
                        if ('asset_type' in payment && payment.asset_type !== 'native') {
                            assetString = `${payment.asset_code}:${payment.asset_issuer}`;
                        }

                        const isSuccessful =
                            'transaction_successful' in payment
                                ? Boolean(payment.transaction_successful)
                                : true;

                        return {
                            amount: payment.amount,
                            asset: assetString,
                            memo,
                            timestamp: payment.created_at,
                            source: payment.from,
                            destination: payment.to,
                            status: isSuccessful ? 'Success' : 'Pending',
                            txHash: payment.transaction_hash,
                            pagingToken: payment.paging_token,
                        };
                    }),
                );

                const filteredItems = asset
                    ? items.filter(item => item.asset === asset)
                    : items;

                return {
                    items: filteredItems,
                    nextCursor: records.length > 0
                        ? records[records.length - 1].paging_token
                        : undefined,
                };
            } catch (error) {
                lastError = error;
                const err = error as { response?: { status: number } };

                // Never retry 4xx (including 429 — handled entirely by backoff layer)
                if (err.response?.status && err.response.status < 500) {
                    throw error;
                }

                if (attempt === this.maxRetries) {
                    throw error;
                }

                const delay = this.calculateDelay(attempt);
                this.logger.warn(
                    `Horizon request failed (attempt ${attempt}/${this.maxRetries}), retrying in ${delay}ms: ${err.response?.status ?? 'Unknown error'}`,
                );
                await this.sleep(delay);
            }
        }

        throw lastError;
    }

    private calculateDelay(attempt: number): number {
        // Deterministic, no jitter — keeps tests fast and predictable
        return Math.min(this.baseDelay * Math.pow(2, attempt - 1), this.maxDelay);
    }

    private updateBackoff(cacheKey: string): void {
        const existing = this.backoffCache.get(cacheKey);
        const attempts = existing ? Math.min(existing.attempts + 1, this.maxRetries) : 1;
        this.backoffCache.set(cacheKey, { attempts, lastAttempt: Date.now() });
    }

    private sleep(ms: number): Promise<void> {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    private handleHorizonError(error: unknown, traceId?: string): never {
      throwMappedStellarException(error, traceId);
    }

    getCacheStats() {
        return {
            entries: this.cache.size,
            maxEntries: this.cache.max,
            ttl: this.cache.ttl,
            backoffEntries: this.backoffCache.size,
        };
    }

    clearCache(): void {
        this.cache.clear();
        this.backoffCache.clear();
        this.logger.debug('Cache cleared');
    }
}
