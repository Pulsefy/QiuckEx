import { FundingHelperService } from './funding-helper.service';
import { DeploymentService } from './deployment.service';
import { HorizonService } from '../stellar/horizon.service';
import { AppConfigService } from '../config';
import { ContractRegistryService } from '../contracts/contract-registry.service';

describe('Soroban tooling services', () => {
  const mockConfig = { network: 'testnet' } as AppConfigService;

  describe('FundingHelperService', () => {
    it('returns faucet guidance when the account is missing', async () => {
      const service = new FundingHelperService(
        { getAccount: jest.fn().mockResolvedValue(null) } as unknown as HorizonService,
        mockConfig,
      );

      const result = await service.checkFunding({ accountId: 'GTEST' });
      expect(result.ready).toBe(false);
      expect(result.accountExists).toBe(false);
      expect(result.faucetUrl).toContain('laboratory.stellar.org');
    });

    it('marks the account ready when the minimum XLM balance is present', async () => {
      const service = new FundingHelperService(
        {
          getAccount: jest.fn().mockResolvedValue({
            balances: [{ asset_type: 'native', balance: '10.5000000' }],
          }),
        } as unknown as HorizonService,
        mockConfig,
      );

      const result = await service.checkFunding({ accountId: 'GTEST', minBalanceXlm: 5 });
      expect(result.ready).toBe(true);
      expect(result.currentBalanceXlm).toBe('10.5000000');
    });
  });

  describe('DeploymentService', () => {
    it('produces a dry-run plan with idempotency hints from the registry', async () => {
      const fundingHelperService = {
        checkFunding: jest.fn().mockResolvedValue({ ready: true }),
      } as unknown as FundingHelperService;
      const contractRegistryService = {
        getRegistry: jest.fn().mockResolvedValue({
          data: {
            quickex: {
              id: 'C123',
              wasmHash: 'not-the-same-hash',
              version: 1,
            },
          },
        }),
      } as unknown as ContractRegistryService;

      const service = new DeploymentService(
        mockConfig,
        fundingHelperService,
        contractRegistryService,
      );

      const result = await service.planDeployment({
        network: 'testnet',
        source: 'test',
        dryRun: true,
        adminPublicKey: 'GADMIN',
        contracts: [
          {
            name: 'quickex',
            wasmPath: 'README.md',
          },
        ],
      });

      expect(result.ready).toBe(true);
      expect(result.commands[0]).toContain('soroban contract install');
      expect(result.contracts[0].wasmExists).toBe(true);
    });
  });
});
