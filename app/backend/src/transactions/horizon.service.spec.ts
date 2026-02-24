// Mock stellar-sdk BEFORE importing HorizonService
jest.mock('stellar-sdk', () => {
    const mockServer = {
        operations: jest.fn().mockReturnThis(),
        forAccount: jest.fn().mockReturnThis(),
        order: jest.fn().mockReturnThis(),
        limit: jest.fn().mockReturnThis(),
        cursor: jest.fn().mockReturnThis(),
        call: jest.fn(),
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

describe('HorizonService', () => {
    let service: HorizonService;
    let mockServer: any;

    beforeEach(async () => {
        // Create a mock server instance before creating the service
        const mockServerInstance = {
            operations: jest.fn().mockReturnThis(),
            forAccount: jest.fn().mockReturnThis(),
            order: jest.fn().mockReturnThis(),
            limit: jest.fn().mockReturnThis(),
            cursor: jest.fn().mockReturnThis(),
            call: jest.fn(),
        };
        
        const mockAppConfigService = {
            network: 'testnet',
            cacheMaxItems: 500,
            cacheTtlMs: 60000,
        };
        
        // Mock the Horizon.Server constructor to return our mock instance
        (require('stellar-sdk').Horizon.Server as jest.MockedFunction<any>).mockReturnValue(mockServerInstance);

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
        mockServer = (service as any)['server'];
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
            if (typeof response === 'object' && response !== null) {
                expect((response as any).error).toContain('Service temporarily unavailable due to rate limiting');
            } else {
                expect(response).toContain('Service temporarily unavailable due to rate limiting');
            }
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
});