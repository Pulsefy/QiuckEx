import { ConfigService } from '@nestjs/config';
import * as StellarSdk from '@stellar/stellar-sdk';
import { ContractViewsService } from './contract-views.service';

function makeEscrowValue(expiryLedger: number): StellarSdk.xdr.ScVal {
  const fields: Record<string, StellarSdk.xdr.ScVal> = {
    depositor: StellarSdk.xdr.ScVal.scvString('depositor'),
    beneficiary: StellarSdk.xdr.ScVal.scvString('beneficiary'),
    amount: StellarSdk.xdr.ScVal.scvString('100'),
    asset_code: StellarSdk.xdr.ScVal.scvString('XLM'),
    released: StellarSdk.xdr.ScVal.scvBool(false),
    refunded: StellarSdk.xdr.ScVal.scvBool(false),
    expiry_ledger: StellarSdk.xdr.ScVal.scvU32(expiryLedger),
  };

  return StellarSdk.xdr.ScVal.scvMap(
    Object.entries(fields).map(
      ([key, value]) => new StellarSdk.xdr.ScMapEntry({
        key: StellarSdk.xdr.ScVal.scvSymbol(key),
        val: value,
      }),
    ),
  );
}

describe('ContractViewsService escrow expiry', () => {
  it.each([
    { currentLedger: 101, expiryLedger: 100, expired: true },
    { currentLedger: 99, expiryLedger: 100, expired: false },
  ])(
    'reports expired=$expired when current ledger is $currentLedger and expiry is $expiryLedger',
    async ({ currentLedger, expiryLedger, expired }) => {
      const configService = {
        get: jest.fn((key: string) =>
          key === 'QUICKEX_CONTRACT_ID'
            ? 'contract-id'
            : key === 'stellar'
              ? { horizonBaseUrl: 'https://horizon-testnet.stellar.org' }
              : undefined,
        ),
      } as unknown as ConfigService;
      const service = new ContractViewsService(configService);
      const call = jest.fn().mockResolvedValue({
        records: [{ sequence: currentLedger }],
      });
      const horizon = {
        ledgers: jest.fn().mockReturnValue({
          order: jest.fn().mockReturnValue({
            limit: jest.fn().mockReturnValue({ call }),
          }),
        }),
      } as unknown as StellarSdk.Horizon.Server;

      Object.defineProperty(service, 'horizon', { value: horizon });
      Object.defineProperty(service, 'simulateContractView', {
        value: jest.fn().mockResolvedValue(makeEscrowValue(expiryLedger)),
      });

      const summary = await service.getEscrowSummary('escrow-id');

      expect(summary.expired).toBe(expired);
      expect(call).toHaveBeenCalledTimes(1);
    },
  );
});
