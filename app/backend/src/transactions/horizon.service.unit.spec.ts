// Mock @stellar/stellar-sdk BEFORE importing HorizonService
jest.mock('@stellar/stellar-sdk', () => {
    const mockServer = {
        operations: jest.fn().mockReturnThis(),
        forAccount: jest.fn().mockReturnThis(),
        order: jest.fn().mockReturnThis(),
        limit: jest.fn().mockReturnThis(),
        cursor: jest.fn().mockReturnThis(),
        accounts: jest.fn().mockReturnThis(),
        accountId: jest.fn().mockReturnThis(),
        payments: jest.fn().mockReturnThis(),
        call: jest.fn(),
        httpClient: { defaults: {} },
    };
    
    return {
        Horizon: {
            Server: jest.fn(() => mockServer),
        },
    };
});

import { Test, TestingModule } from '@nestjs/testing';
import { HorizonService } from './horizon.service';
import { AppConfigService } from '../config/app-config.service';
import { HttpException, HttpStatus } from '@nestjs/common';

// The new helpers issue real fetch() calls; mock them for the whole suite.
global.fetch = jest.fn();

describe('HorizonService', () => {
    let service: HorizonService;
    let mockServer: Record<string, jest.Mock>;

    beforeEach(async () => {
        const mockAppConfigService = {
            network: 'testnet',
            cacheMaxItems: 500,
            cacheTtlMs: 60000,
            horizonRequestTimeoutMs: 10000,
        };

        const module: TestingModule = await Test.createTestingModule({
            providers: [
                HorizonService,
                {
                    provide: AppConfigService,
                    useValue: mockAppConfigService,
                },
            ],
        }).compile();

        service = module.get<HorizonService>(HorizonService);
        
        // Get the actual mock server instance that was created
        mockServer = service['server'] as unknown as Record<string, jest.Mock>;
        
        // Clear cache and reset mocks between tests
        service.clearCache();
        jest.clearAllMocks();
    });

    it('should be defined', () => {
        expect(service).toBeDefined();
    });

    describe('getPayments', () => {
        const mockAccountId = 'GD123';
        const mockRecords = [
            {
                type: 'payment',
                amount: '10.0',
                asset_type: 'native',
                created_at: '2024-01-01T00:00:00Z',
                transaction_hash: 'hash1',
                paging_token: 'token1',
                transaction: jest.fn().mockResolvedValue({ memo: 'test memo' }),
            },
            {
                type: 'create_account', // Should be filtered out
                paging_token: 'token2',
            },
        ];

        it('should fetch and normalize payments correctly', async () => {
            mockServer.call.mockResolvedValue({ records: mockRecords });

            const result = await service.getPayments(mockAccountId);

            expect(result.items).toHaveLength(1);
            expect(result.items[0]).toEqual({
                amount: '10.0',
                asset: 'XLM',
                memo: 'test memo',
                timestamp: '2024-01-01T00:00:00Z',
                source: undefined,
                destination: undefined,
                status: 'Success',
                txHash: 'hash1',
                pagingToken: 'token1',
            });
            expect(result.nextCursor).toBe('token2');
        });

        it('should return cached results on subsequent calls', async () => {
            mockServer.call.mockResolvedValue({ records: mockRecords });

            // First call
            await service.getPayments(mockAccountId);
            expect(mockServer.call).toHaveBeenCalledTimes(1);

            // Second call (should be cached)
            const result = await service.getPayments(mockAccountId);
            expect(mockServer.call).toHaveBeenCalledTimes(1);
            expect(result.items).toHaveLength(1);
        });

        it('should handle 429 rate limit error', async () => {
            // Clear cache to ensure clean state
            service.clearCache();

            const error = {
                response: {
                    status: 429,
                },
            };
            mockServer.call.mockRejectedValue(error);

            // First call should fail with rate limit error and create backoff entry
            await expect(service.getPayments(mockAccountId)).rejects.toThrow(
                new HttpException(
                    'Horizon service rate limit exceeded. Please try again later.',
                    HttpStatus.SERVICE_UNAVAILABLE,
                ),
            );

            // Second call should be blocked by backoff with timing information
            await expect(service.getPayments(mockAccountId)).rejects.toThrow(HttpException);

            // Extract the error to check specific properties
            let thrownError: HttpException | undefined;
            try {
                await service.getPayments(mockAccountId);
            } catch (err) {
                thrownError = err as HttpException;
            }

            expect(thrownError).toBeDefined();
            expect(thrownError).toBeInstanceOf(HttpException);
            // Check the response body for the expected message instead of the exception message
            const response = thrownError!.getResponse();
            const responseWithError = (typeof response === 'object' && response !== null) ?
                             (response as Record<string,unknown>).error : response;
            const responseMessage =
                typeof responseWithError === 'string'
                    ? responseWithError
                    : JSON.stringify(responseWithError);
            expect(responseMessage).toMatch(/Service temporarily unavailable due to rate limiting|Horizon service rate limit exceeded/i);
            expect(thrownError!.getStatus()).toBe(HttpStatus.SERVICE_UNAVAILABLE);
        }, 10000); // Increase timeout for backoff

        it('should filter by asset if provided', async () => {
            const complexRecords = [
                {
                    type: 'payment',
                    amount: '1.0',
                    asset_type: 'native',
                    created_at: '2024-01-01T00:00:00Z',
                    transaction_hash: 'hash1',
                    paging_token: 'token1',
                    transaction: jest.fn().mockResolvedValue({ memo: 'native' }),
                },
                {
                    type: 'payment',
                    amount: '2.0',
                    asset_type: 'credit_alphanum4',
                    asset_code: 'USDC',
                    asset_issuer: 'GUSDC',
                    created_at: '2024-01-01T00:01:00Z',
                    transaction_hash: 'hash2',
                    paging_token: 'token2',
                    transaction: jest.fn().mockResolvedValue({ memo: 'usdc' }),
                },
            ];
            mockServer.call.mockResolvedValue({ records: complexRecords });

            const result = await service.getPayments(mockAccountId, 'USDC:GUSDC');

            expect(result.items).toHaveLength(1);
            expect(result.items[0].asset).toBe('USDC:GUSDC');
            expect(result.items[0].amount).toBe('2.0');
        });
    });

    describe('request timeout configuration', () => {
        it('applies HORIZON_REQUEST_TIMEOUT_MS to the SDK HTTP client', () => {
            const server = service['server'] as unknown as {
                httpClient: { defaults: { timeout?: number } };
            };

            expect(server.httpClient.defaults.timeout).toBe(10000);
        });
    });

    describe('getAccount', () => {
        const accountId = 'GNEWLYCREATEDACCOUNT123456789ABCDEFGHIJKLMN';

        it('fetches the account through a timed fetch', async () => {
            (global.fetch as jest.Mock).mockResolvedValueOnce({
                ok: true,
                status: 200,
                json: async () => ({
                    account_id: accountId,
                    created_at: '2026-10-01T00:00:00Z',
                }),
            } as Response);

            const result = await service.getAccount(accountId);

            expect(result).toEqual({
                account_id: accountId,
                created_at: '2026-10-01T00:00:00Z',
            });
            expect(global.fetch as jest.Mock).toHaveBeenCalledWith(
                `https://horizon-testnet.stellar.org/accounts/${accountId}`,
                expect.objectContaining({ signal: expect.any(AbortSignal) }),
            );
        });

        it('returns null when the account does not exist (404)', async () => {
            (global.fetch as jest.Mock).mockResolvedValueOnce({
                ok: false,
                status: 404,
            } as Response);

            await expect(service.getAccount(accountId)).resolves.toBeNull();
        });

        it('maps error statuses onto the shared Horizon error handling', async () => {
            (global.fetch as jest.Mock).mockResolvedValueOnce({
                ok: false,
                status: 429,
            } as Response);

            await expect(service.getAccount(accountId)).rejects.toThrow(
                new HttpException(
                    'Horizon service rate limit exceeded. Please try again later.',
                    HttpStatus.SERVICE_UNAVAILABLE,
                ),
            );
        });

        it('aborts a hanging request at the configured timeout', async () => {
            jest.useFakeTimers();
            try {
                (global.fetch as jest.Mock).mockImplementationOnce(
                    (_url: unknown, init?: { signal?: AbortSignal }) =>
                        new Promise((_resolve, reject) => {
                            init?.signal?.addEventListener('abort', () =>
                                reject(
                                    new DOMException(
                                        'This operation was aborted',
                                        'AbortError',
                                    ),
                                ),
                            );
                        }),
                );

                const pending = service.getAccount(accountId).catch((error) => error);
                await jest.advanceTimersByTimeAsync(10000);
                const error = await pending;

                expect(error).toBeInstanceOf(Error);
                expect(error.message).toBe(
                    'Horizon request timed out after 10000ms',
                );
            } finally {
                jest.useRealTimers();
            }
        });
    });

    describe('getPaymentsSince', () => {
        const accountId = 'GPAYMENTSHISTORYACCOUNT123456789ABCDEFGHIJKLM';
        const since = '2026-10-17T09:00:00.000Z';

        it('requests payments created after the cutoff through a timed fetch', async () => {
            const records = [
                {
                    type: 'payment',
                    amount: '5.0',
                    asset_type: 'native',
                    created_at: '2026-10-17T09:30:00Z',
                },
                {
                    type: 'create_account',
                    created_at: '2026-10-17T09:20:00Z',
                },
            ];
            (global.fetch as jest.Mock).mockResolvedValueOnce({
                ok: true,
                status: 200,
                json: async () => ({ _embedded: { records } }),
            } as Response);

            const result = await service.getPaymentsSince(accountId, since);

            expect(result).toEqual(records);
            expect(global.fetch as jest.Mock).toHaveBeenCalledWith(
                `https://horizon-testnet.stellar.org/accounts/${accountId}/payments` +
                    `?limit=100&order=desc&created_at:gt=${encodeURIComponent(since)}`,
                expect.objectContaining({ signal: expect.any(AbortSignal) }),
            );
        });

        it('honours a custom limit', async () => {
            (global.fetch as jest.Mock).mockResolvedValueOnce({
                ok: true,
                status: 200,
                json: async () => ({ _embedded: { records: [] } }),
            } as Response);

            await service.getPaymentsSince(accountId, since, 25);

            expect((global.fetch as jest.Mock).mock.calls[0][0]).toContain(
                'limit=25',
            );
        });

        it('returns an empty list when the account has no payment history (404)', async () => {
            (global.fetch as jest.Mock).mockResolvedValueOnce({
                ok: false,
                status: 404,
            } as Response);

            await expect(service.getPaymentsSince(accountId, since)).resolves.toEqual([]);
        });

        it('maps error statuses onto the shared Horizon error handling', async () => {
            (global.fetch as jest.Mock).mockResolvedValueOnce({
                ok: false,
                status: 503,
            } as Response);

            await expect(service.getPaymentsSince(accountId, since)).rejects.toThrow(
                new HttpException(
                    'Horizon service temporarily unavailable. Please try again later.',
                    HttpStatus.SERVICE_UNAVAILABLE,
                ),
            );
        });
    });
});