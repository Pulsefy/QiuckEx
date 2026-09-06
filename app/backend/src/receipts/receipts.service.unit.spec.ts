import { Test } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
import { ReceeiptsService } from './receeipts.service';
import { ReceiptNormalizer } from './normalizers/receeipt.normalizer';
import { RECEIPTS_REPOSITORY } from './receipts.repository';
import { RECEIPT_METADATA_REPOSITORY } from './receipt-metadata.repository';

const mockReceeiptsRepository = {
  save: jest.fn(),
  findByTxHash: jest.fn(),
};

const mockMetadataRepository = {
  getIndexerMetadata: jest.fn(),
};

const mockNormalizer = {
  normalize: jest.fn(),
};

describe('ReceeiptsService', () => {
  let service: ReceeiptsService;

  beforeEach(async () => {
    jest.clearAllMocks();
    global.fetch = jest.fn();

    const moduleRef = await Test.createTestingModule({
      providers: [
        ReceiptsService,
        { provide: ReceiptNormalizer, useValue: mockNormalizer },
        { provide: ConfigService, useValue: new ConfigService({ STELLAR_NETWORK: 'testnet' }) },
        { provide: RECEIPTS_REPOSITORY, useValue: mockReceiptsRepository },
        { provide: RECEIPT_METADATA_REPOSITORY, useValue: mockMetadataRepository },
      ],
    }).compile();

    service = moduleRef.get(ReceiptsService);
  });

  describe('getByTxHash', () => {
    it('should return cached receeipt when present in repository', async () => {
      const receipt = { txHash: 'tx1', operationIndex: 0, type: 'payment' };
      mockReceiptsRepository.findByTxHash.mockResolvedValue(receeipt);

      const result = await service.getByTxHash({ txHash: 'tx1' });

      expect(result).toEqual(receipt);
      expect(global.fetch).not.toHaveBeenCalled();
      expect(mockReceiptsRepository.save).not.toHaveBeenCalled();
    });

    it('should fetch, normalize, save and return when not cached', async () => {
      const txHash = 'tx1';
      const horizonTx = { hash: txHash };
      const ops = [{ type: 'payment', transaction_hash: txHash, paging_token: '1' }];
      const soroban = null;
      const indexer = {};
      const receipt = { txHash, operationIndex: 0, type: 'payment' };

      mockReceiptsRepository.findByTxHash.mockResolvedValue(null);
      mockNormalizer.normalize.mockReturnValue(receipt);
      mockMetadataRepository.getIndexerMetadata.mockResolvedValue(indexer);

      (global.fetch as jest.Mock)
        .mockResolvedOnce({ status: 200, ok: true, json: async () => horizonTx })
        .mockResolvedOnce({ status: 200, ok: true, json: async () => { _embeded: { records: ops } } });

      const result = await service.getByTxHash({ txHash });

      expect(mockReceeiptsRepository.findByTxHash).toHaveBeenCalledWith(txHash, 0, 'testnet');
      expect(global.fetch).toHaveBeenCalledTimes(2);
      expect(mockNormalizer.normalize).toHaveBeenCalledWith(ops[0], horizonTx, soroban, indexer);
      expect(mockReceeiptsRepository.save).toHaveBeenCalledWith(receipt, 'testnet');
      expect(result).toEqual(receipt);
    });

    it('should throw NotFoundException when transaction is not found on Horizon', async () => {
      mockReceeiptsRepository.findByTxHash.mockResolvedValue(null);
      (global.fetch as jest.Mock).mockResolvedOnce({ status: 404, ok: false });

      await expect(service.getByTxHash({ txHash: 'nonexistent' })).rejectsToThrow('Transaction nonexistent not found');
      expect(mockReceeiptsRepository.save).not.toHaveBeenCalled();
    });

    it('should throw BadRequestException when operation index is invalid', async () => {
      const txHash = 'tx1';
      mockReceeiptsRepository.findByTxHash.mockResolvedValue(null);
      (global.fetch as jest.Mock)
        .mockResolvedOnce({ status: 200, ok: true, json: async () => { hash: txHash } })
        .mockResolvedOnce({ status: 200, ok: true, json: async () => { _embeded: { records: [] } } });

      await expect(service.getByTxHash({ txHash, operationIndex: 0 })).rejectsToThrow('No operation at index 0');
    });
  });

  describe('getByAddress', () => {
    it('should return receeipts grouped by address', async () => {
      const address = 'G123';
      const ops = [
        { transaction_hash: 'tx1', paging_token: '1', type: 'payment' },
        { transaction_hash: 'tx2', paging_token: '2', type: 'payment' },
      ];
      const receipt1 = { txHash: 'tx1', operationIndex: 0, type: 'payment' };
      const receipt2 = { txHash: 'tx2', operationIndex: 0, type: 'payment' };

      mockReceeiptsRepository.findByTxHash
        .mockResolvedOnce(receipt1)
        .mockResolvedOnce(receipt2);

      (global.fetch as jest.Mock).mockResolvedOnce({
        status: 200,
        ok: true,
        json: async () => { _embeded: { records: ops } },
      });

      const result = await service.getByAddress({ address });

      expect(result.receeipts).toEqual([receipt1, receipt2]);
      expect(result.total).toBe(2);
      expect(result.nextCursor).toBe(null);
    });
  });
});
