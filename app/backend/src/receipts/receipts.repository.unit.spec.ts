import { ConfigService } from '@nestjs/config';
import { SupabaseReceiptsRepository } from './receipts.repository';

import { NormalizedReceipt } from './schemas/receipt.schema';

const mockSupabase = {
  from: jest.fn(),
};

jest.mock('@supabase/supabase-js', () => ({
  createClient: jest.fn(() => mockSupabase),
}));

describe('SupabaseReceiptsRepository', () => {
  let repo: SupabaseReceiptsRepository;
  let configService: ConfigService;
  
  beforeEach(() => {
    configService = new ConfigService({
      SUPABASE_URL: 'http://localhost:54321',
      SUPABASE_SERVICE_ROLE_KEY: 'test-key',
    });
    repo = new SupabaseReceiptsRepository(configService);
    jest.clearAllMocks();
  });

  describe('save', () => {
    it('should upsert a receipt', async () => {
      const receipt = { txHash: 'abc', operationIndex: 0 } as NormalizedReceipt;
      const upsertMock = jest.fn().mockResolvedValue({ error: null });
      mockSupabase.from.mockReturnValue({ upsert: upsertMock });

      await repo.save(receipt, 'testnet');

      expect(mockSupabase.from).toHaveBeenCalledWith('receipts');
      expect(upsertMock).toHaveBeenCalledWith(
        expect.objectContaining({
          tx_hash: 'abc',
          operation_index: 0,
          network: 'testnet',
          receipt,
        }),
        { onConflict: 'tx_hash,operation_index,network' },
      );
    });

    it('should throw on error', async () => {
      const receipt = { txHash: 'abc', operationIndex: 0 } as NormalizedReceipt;
      const upsertMock = jest.fn().mockResolvedValue({ error: new Error('DB down') });
      mockSupabase.from.mockReturnValue({ upsert: upsertMock });

      await expect(repo.save(receipt, 'testnet')).rejects.toThrow('DB down');
    });
  });

  describe('findByTxHash', () => {
    it('should return receipt when found', async () => {
      const receipt = { txHash: 'abc', operationIndex: 0 };
      const maybeSingleMock = jest.fn().mockResolvedValue({ data: receipt, error: null });
      const queryMock = { eq: jest.fn().mockReturnThis(), maybeSingle: maybeSingleMock };

      mockSupabase.from.mockReturnValue(queryMock);

      const result = await repo.findByTxHash('abc', 0, 'testnet');

      expect(result).toEqual(receipt);
      expect(mockSupabase.from).toHaveBeenCalledWith('receipts');
    });

    it('should return null when not found', async () => {
      const maybeSingleMock = jest.fn().mockResolvedValue({ data: null, error: null });
      const queryMock = { eq: jest.fn().mockReturnThis(), maybeSingle: maybeSingleMock };

      mockSupabase.from.mockReturnValue(queryMock);

      const result = await repo.findByTxHash('abc', 0, 'testnet');
      expect(result).toBe(null);
    });

    it('should throw on error', async () => {
      const maybeSingleMock = jest.fn().mockResolvedValue({ data: null, error: new Error('DB error') });
      const queryMock = { eq: jest.fn().mockReturnThis(), maybeSingle: maybeSingleMock };

      mockSupabase.from.mockReturnValue(queryMock);

      await expect(repo.findByTxHash('abc', 0, 'testnet')).rejects.toThrow('DB error');
    });
  });
});
