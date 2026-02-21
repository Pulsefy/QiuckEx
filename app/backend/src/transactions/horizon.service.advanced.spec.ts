import { Test, TestingModule } from '@nestjs/testing';
import { HorizonService } from './horizon.service';
import { AppConfigService } from '../config/app-config.service';
import { HttpException, HttpStatus } from '@nestjs/common';

// Mock stellar-sdk
jest.mock('stellar-sdk', () => {
    return {
        Horizon: {
            Server: jest.fn().mockImplementation(() => ({
                operations: jest.fn().mockReturnThis(),
                forAccount: jest.fn().mockReturnThis(),
                order: jest.fn().mockReturnThis(),
                limit: jest.fn().mockReturnThis(),
                cursor: jest.fn().mockReturnThis(),
                call: jest.fn(),
            })),
        },
    };
});

describe('HorizonService - Advanced Features', () => {
    let service: HorizonService;
    let mockServer: Record<string, jest.Mock>;

    beforeEach(async () => {
        const module: TestingModule = await Test.createTestingModule({
            providers: [
                HorizonService,
                {
                    provide: AppConfigService,
                    useValue: {
                        network: 'testnet',
                        cacheMaxItems: 100,
                        cacheTtlMs: 5000, // 5 seconds for testing
                    },
                },
            ],
        }).compile();

        service = module.get<HorizonService>(HorizonService);
        mockServer = service['server'] as unknown as typeof mockServer;
        
        // Clear cache between tests
        service.clearCache();
    });

    it('should be defined', () => {
        expect(service).toBeDefined();
    });

    describe('Caching Behavior', () => {
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
        ];

        it('should cache results and serve from cache on subsequent calls', async () => {
            mockServer.call.mockResolvedValue({ records: mockRecords });

            // First call - should hit Horizon
            const result1 = await service.getPayments(mockAccountId);
            expect(mockServer.call).toHaveBeenCalledTimes(1);
            expect(result1.items).toHaveLength(1);

            // Second call with same parameters - should be cached
            const result2 = await service.getPayments(mockAccountId);
            expect(mockServer.call).toHaveBeenCalledTimes(1); // No additional call
            expect(result2).toEqual(result1);
        });

        it('should cache different queries separately', async () => {
            const records1 = [...mockRecords];
            const records2 = [{
                ...mockRecords[0],
                amount: '20.0',
                transaction_hash: 'hash2',
                paging_token: 'token2',
            }];
            
            mockServer.call
                .mockResolvedValueOnce({ records: records1 })
                .mockResolvedValueOnce({ records: records2 });

            // Different limit parameters
            const result1 = await service.getPayments(mockAccountId, undefined, 10);
            const result2 = await service.getPayments(mockAccountId, undefined, 20);

            expect(mockServer.call).toHaveBeenCalledTimes(2);
            expect(result1.items[0].amount).toBe('10.0');
            expect(result2.items[0].amount).toBe('20.0');
        });

        it('should respect cache TTL and fetch fresh data after expiration', async () => {
            mockServer.call.mockResolvedValue({ records: mockRecords });

            // First call
            await service.getPayments(mockAccountId);
            
            // Manipulate cache to expire (simulate time passing)
            const cache = service['cache'];
            const cacheKey = `testnet:${mockAccountId}:any:20:start`;
            const entry = cache.get(cacheKey);
            if (entry) {
                // Force expiration by setting created time to past
                (cache as any).set(cacheKey, entry, { ttl: 1 }); // 1ms TTL
            }
            
            // Wait a bit to ensure expiration
            await new Promise(resolve => setTimeout(resolve, 10));
            
            // Second call should hit Horizon again
            await service.getPayments(mockAccountId);
            expect(mockServer.call).toHaveBeenCalledTimes(2);
        });

        it('should cache asset-filtered results separately', async () => {
            const nativeRecords = [{
                type: 'payment',
                amount: '10.0',
                asset_type: 'native',
                created_at: '2024-01-01T00:00:00Z',
                transaction_hash: 'hash1',
                paging_token: 'token1',
                transaction: jest.fn().mockResolvedValue({ memo: 'native' }),
            }];
            
            const usdcRecords = [{
                type: 'payment',
                amount: '20.0',
                asset_type: 'credit_alphanum4',
                asset_code: 'USDC',
                asset_issuer: 'GUSDC',
                created_at: '2024-01-01T00:01:00Z',
                transaction_hash: 'hash2',
                paging_token: 'token2',
                transaction: jest.fn().mockResolvedValue({ memo: 'usdc' }),
            }];
            
            mockServer.call
                .mockResolvedValueOnce({ records: nativeRecords })
                .mockResolvedValueOnce({ records: usdcRecords });

            // Cache native asset results
            await service.getPayments(mockAccountId, 'XLM');
            
            // Cache USDC asset results
            await service.getPayments(mockAccountId, 'USDC:GUSDC');
            
            // Should make two separate calls
            expect(mockServer.call).toHaveBeenCalledTimes(2);
        });
    });

    describe('Backoff Mechanism', () => {
        const mockAccountId = 'GD123';

        it('should implement exponential backoff on 429 errors', async () => {
            const error429 = { response: { status: 429 } };
            mockServer.call.mockRejectedValue(error429);

            // First failure - should create backoff entry
            await expect(service.getPayments(mockAccountId)).rejects.toThrow(
                new HttpException(
                    'Horizon service rate limit exceeded. Please try again later.',
                    HttpStatus.SERVICE_UNAVAILABLE,
                ),
            );

            // Second call should be blocked by backoff with specific message
            await expect(service.getPayments(mockAccountId)).rejects.toThrow(
                new HttpException(
                    expect.stringContaining('Service temporarily unavailable due to rate limiting'),
                    HttpStatus.SERVICE_UNAVAILABLE,
                ),
            );

            // Should not make additional Horizon calls during backoff
            expect(mockServer.call).toHaveBeenCalledTimes(1);
        }, 10000);

        it('should implement backoff for 5xx errors', async () => {
            const error500 = { response: { status: 500 } };
            mockServer.call.mockRejectedValue(error500);

            // First failure - should create backoff entry
            await expect(service.getPayments(mockAccountId)).rejects.toThrow(
                new HttpException(
                    'Horizon service encountered an internal error.',
                    HttpStatus.BAD_GATEWAY,
                ),
            );

            // Backoff should be in effect with specific message
            await expect(service.getPayments(mockAccountId)).rejects.toThrow(
                new HttpException(
                    expect.stringContaining('Service temporarily unavailable due to rate limiting'),
                    HttpStatus.SERVICE_UNAVAILABLE,
                ),
            );
        }, 10000);

        it('should reset backoff after successful request', async () => {
            const error429 = { response: { status: 429 } };
            const successRecords = [{
                type: 'payment',
                amount: '10.0',
                asset_type: 'native',
                created_at: '2024-01-01T00:00:00Z',
                transaction_hash: 'hash1',
                paging_token: 'token1',
                transaction: jest.fn().mockResolvedValue({ memo: 'test' }),
            }];
            
            // Fail first
            mockServer.call.mockRejectedValueOnce(error429);
            await expect(service.getPayments(mockAccountId)).rejects.toThrow();
            
            // Wait for backoff to expire (simulate time passing)
            await new Promise(resolve => setTimeout(resolve, 100));
            
            // Succeed on retry
            mockServer.call.mockResolvedValueOnce({ records: successRecords });
            const result = await service.getPayments(mockAccountId);
            
            expect(result.items).toHaveLength(1);
            // Backoff should be reset, so next call should work
            mockServer.call.mockResolvedValueOnce({ records: successRecords });
            await service.getPayments(mockAccountId);
            expect(mockServer.call).toHaveBeenCalledTimes(3);
        }, 10000);

        it('should not apply backoff for 4xx client errors', async () => {
            const error400 = { response: { status: 400, data: { error: 'invalid account' } } };
            mockServer.call.mockRejectedValue(error400);

            await expect(service.getPayments(mockAccountId)).rejects.toThrow(
                new HttpException(
                    'Invalid request to Horizon service',
                    HttpStatus.BAD_REQUEST,
                ),
            );

            // Should still allow immediate retry (no backoff) - but with different error handling
            // The second call will also fail with 400, but won't trigger backoff
            await expect(service.getPayments(mockAccountId)).rejects.toThrow(
                new HttpException(
                    'Invalid request to Horizon service',
                    HttpStatus.BAD_REQUEST,
                ),
            );
            // Should make 2 calls since no backoff for 4xx
            expect(mockServer.call).toHaveBeenCalledTimes(2);
        }, 10000);
    });

    describe('Retry Logic', () => {
        const mockAccountId = 'GD123';
        const mockRecords = [{
            type: 'payment',
            amount: '10.0',
            asset_type: 'native',
            created_at: '2024-01-01T00:00:00Z',
            transaction_hash: 'hash1',
            paging_token: 'token1',
            transaction: jest.fn().mockResolvedValue({ memo: 'test' }),
        }];

        it('should retry on 5xx errors with exponential backoff', async () => {
            const error500 = { response: { status: 500 } };
            
            mockServer.call
                .mockRejectedValueOnce(error500)  // Attempt 1 - fail
                .mockRejectedValueOnce(error500)  // Attempt 2 - fail
                .mockResolvedValueOnce({ records: mockRecords }); // Attempt 3 - succeed

            const result = await service.getPayments(mockAccountId);
            
            expect(result.items).toHaveLength(1);
            expect(mockServer.call).toHaveBeenCalledTimes(3);
        });

        it('should not retry on 4xx errors', async () => {
            const error400 = { response: { status: 400 } };
            mockServer.call.mockRejectedValue(error400);

            await expect(service.getPayments(mockAccountId)).rejects.toThrow();
            expect(mockServer.call).toHaveBeenCalledTimes(1);
        });

        it('should respect maximum retry attempts', async () => {
            const error500 = { response: { status: 500 } };
            mockServer.call.mockRejectedValue(error500);

            await expect(service.getPayments(mockAccountId)).rejects.toThrow();
            expect(mockServer.call).toHaveBeenCalledTimes(3); // Max retries
        });
    });

    describe('Cache Statistics', () => {
        it('should provide cache statistics', () => {
            const stats = service.getCacheStats();
            
            expect(stats).toHaveProperty('entries');
            expect(stats).toHaveProperty('maxEntries');
            expect(stats).toHaveProperty('ttl');
            expect(stats).toHaveProperty('backoffEntries');
            expect(stats.maxEntries).toBe(100);
            expect(stats.ttl).toBe(5000);
        });

        it('should track cache entries correctly', async () => {
            const mockRecords = [{
                type: 'payment',
                amount: '10.0',
                asset_type: 'native',
                created_at: '2024-01-01T00:00:00Z',
                transaction_hash: 'hash1',
                paging_token: 'token1',
                transaction: jest.fn().mockResolvedValue({ memo: 'test' }),
            }];
            
            mockServer.call.mockResolvedValue({ records: mockRecords });
            
            // Initial state
            let stats = service.getCacheStats();
            expect(stats.entries).toBe(0);
            
            // After caching
            await service.getPayments('account1');
            stats = service.getCacheStats();
            expect(stats.entries).toBe(1);
            
            // Clear cache
            service.clearCache();
            stats = service.getCacheStats();
            expect(stats.entries).toBe(0);
        });
    });

    describe('Edge Cases', () => {
        it('should handle empty transaction results', async () => {
            mockServer.call.mockResolvedValue({ records: [] });
            
            const result = await service.getPayments('emptyAccount');
            expect(result.items).toHaveLength(0);
            expect(result.nextCursor).toBeUndefined();
        });

        it('should handle transactions without memos', async () => {
            const records = [{
                type: 'payment',
                amount: '10.0',
                asset_type: 'native',
                created_at: '2024-01-01T00:00:00Z',
                transaction_hash: 'hash1',
                paging_token: 'token1',
                transaction: jest.fn().mockRejectedValue(new Error('No memo')),
            }];
            
            mockServer.call.mockResolvedValue({ records });
            
            const result = await service.getPayments('account1');
            expect(result.items[0].memo).toBeUndefined();
            expect(result.items[0].amount).toBe('10.0');
        });

        it('should handle network-specific caching', async () => {
            // Test that the service works with different cache keys
            const records = [{
                type: 'payment',
                amount: '10.0',
                asset_type: 'native',
                created_at: '2024-01-01T00:00:00Z',
                transaction_hash: 'hash1',
                paging_token: 'token1',
                transaction: jest.fn().mockResolvedValue({ memo: 'test' }),
            }];
            
            mockServer.call.mockResolvedValue({ records });
            
            // Test with different parameters to ensure unique cache keys
            await service.getPayments('account1', 'XLM', 10);
            await service.getPayments('account2', 'USDC:GUSDC', 20, 'cursor123');
            
            // Both should succeed and create different cache entries
            expect(mockServer.call).toHaveBeenCalledTimes(2);
        }, 10000);
    });
});