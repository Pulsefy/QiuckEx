import { TransactionsController } from './transactions.controller';
import { HorizonService } from './horizon.service';
import { TransactionsService } from './transaction.service';
import { SimulateOperationDto } from './dto/compose-transaction.dto';

describe('TransactionsController', () => {
  let controller: TransactionsController;
  let mockTransactionService: jest.Mocked<Partial<TransactionsService>>;
  let mockHorizonService: jest.Mocked<Partial<HorizonService>>;

  beforeEach(() => {
    mockTransactionService = {
      simulateOperation: jest.fn(),
    };
    mockHorizonService = {};

    controller = new TransactionsController(
      mockHorizonService as unknown as HorizonService,
      mockTransactionService as unknown as TransactionsService,
    );
  });

  describe('simulateOperation', () => {
    it('delegates to transactionService.simulateOperation and appends correlationId', async () => {
      const dto: SimulateOperationDto = {
        contractId: 'C123',
        method: 'testMethod',
        params: [],
        sourceAccount: 'G123',
      };
      const req = { correlationId: 'test-correlation-id' } as any;

      (mockTransactionService.simulateOperation as jest.Mock).mockResolvedValueOnce({
        success: true,
        details: {
          cpuInstructions: 1000,
          memoryBytes: 0,
          ledgerReads: 2,
          ledgerWrites: 1,
          eventBytes: 50,
        },
      });

      const result = await controller.simulateOperation(dto, req);

      expect(mockTransactionService.simulateOperation).toHaveBeenCalledWith(dto);
      expect(result).toEqual({
        success: true,
        correlationId: 'test-correlation-id',
        details: {
          cpuInstructions: 1000,
          memoryBytes: 0,
          ledgerReads: 2,
          ledgerWrites: 1,
          eventBytes: 50,
        },
      });
    });

    it('returns mapped error response from transactionService when simulation fails', async () => {
      const dto: SimulateOperationDto = {
        contractId: 'C123',
        method: 'testMethod',
        params: [],
        sourceAccount: 'G123',
      };
      const req = { correlationId: 'test-correlation-id-2' } as any;

      (mockTransactionService.simulateOperation as jest.Mock).mockResolvedValueOnce({
        success: false,
        error: 'CONTRACT_UNAUTHORIZED',
        userMessage: 'You are not authorised to perform this operation.',
      });

      const result = await controller.simulateOperation(dto, req);

      expect(mockTransactionService.simulateOperation).toHaveBeenCalledWith(dto);
      expect(result).toEqual({
        success: false,
        correlationId: 'test-correlation-id-2',
        error: 'CONTRACT_UNAUTHORIZED',
        userMessage: 'You are not authorised to perform this operation.',
      });
    });
  });
});
