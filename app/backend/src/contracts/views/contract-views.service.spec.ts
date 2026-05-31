/**
 * @file test/contracts/contract-views.service.spec.ts
 * Unit tests for ContractViewsService (#439).
 *
 * All Soroban RPC calls are mocked so no real network is needed.
 */

import { NotFoundException } from '@nestjs/common';
import { ContractViewsService } from './contract-views.service';
import { AppConfigService } from '../../config';
import { Test, TestingModule } from '@nestjs/testing';
// import { ConfigService } from '@nestjs/config';
import * as StellarSdk from '@stellar/stellar-sdk';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Builds a minimal ScvMap ScVal from a plain object */
function makeScvMap(entries: Record<string, unknown>): StellarSdk.xdr.ScVal {
  const mapEntries = Object.entries(entries).map(([k, v]) =>
    new StellarSdk.xdr.ScMapEntry({
      key: StellarSdk.nativeToScVal(k, { type: 'symbol' }),
      val: StellarSdk.nativeToScVal(v),
    }),
  );
  return StellarSdk.xdr.ScVal.scvMap(mapEntries);
}

/** Makes a simulated success response with the given return value */
function makeSimSuccess(retval: StellarSdk.xdr.ScVal) {
  return {
    id:              '1',
    latestLedger:    100,
    latestLedgerCloseTime: '0',
    result:          { retval },
    transactionData: '',
    minResourceFee:  '0',
    events:          [],
    restorePreamble: undefined,
  };
}

function makeConfigMock(overrides: Record<string, unknown> = {}) {
  return {
    get: jest.fn().mockImplementation((key: string) => {
      const cfg: Record<string, unknown> = {
        stellar: {
          network:           'testnet',
          networkPassphrase: StellarSdk.Networks.TESTNET,
          sorobanRpcUrl:     'https://soroban-testnet.stellar.org',
        },
        QUICKEX_CONTRACT_ID: 'CTEST000000000000000000000000000000000000000000000000000001',
        ...overrides,
      };
      return cfg[key];
    }),
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('ContractViewsService', () => {
  let service: ContractViewsService;
  let simulateMock: jest.SpyInstance;

  async function build(configOverrides: Record<string, unknown> = {}) {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        ContractViewsService,
        { provide: AppConfigService, useValue: makeConfigMock(configOverrides) },
      ],
    }).compile();
    service = module.get(ContractViewsService);
  }

  function mockSimulate(retval: StellarSdk.xdr.ScVal | null) {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    simulateMock = jest.spyOn(service as any, 'simulateContractView')
      .mockResolvedValue(retval);
  }

  function mockSimulateError(message: string) {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    simulateMock = jest.spyOn(service as any, 'simulateContractView')
      .mockRejectedValue(new Error(message));
  }

  // ── getFeeConfig ──────────────────────────────────────────────────────────

  describe('getFeeConfig()', () => {
    beforeEach(() => build());

    it('returns parsed fee config from contract', async () => {
      const scVal = makeScvMap({
        fee_bps:          50,
        fee_recipient:    'GALICE000000000000000000000000000000000000000000000000000001',
        min_fee_stroops:  '100',
      });
      mockSimulate(scVal);

      const result = await service.getFeeConfig();
      expect(result.feeBps).toBe(50);
      expect(result.feeRecipient).toBe('GALICE000000000000000000000000000000000000000000000000000001');
      expect(result.minFeeStroops).toBe('100');
    });

    it('returns safe defaults when simulation throws', async () => {
      mockSimulateError('RPC timeout');
      const result = await service.getFeeConfig();
      expect(result.feeBps).toBe(50);
      expect(result.feeRecipient).toBe('');
    });

    it('returns safe defaults when QUICKEX_CONTRACT_ID is not set', async () => {
      await build({ QUICKEX_CONTRACT_ID: undefined });
      const result = await service.getFeeConfig();
      expect(result.feeBps).toBe(50);
    });

    it('caches the result — second call does not re-simulate', async () => {
      const scVal = makeScvMap({ fee_bps: 30, fee_recipient: '', min_fee_stroops: '0' });
      mockSimulate(scVal);

      await service.getFeeConfig();
      await service.getFeeConfig();
      expect(simulateMock).toHaveBeenCalledTimes(1);
    });
  });

  // ── getPauseState ─────────────────────────────────────────────────────────

  describe('getPauseState()', () => {
    beforeEach(() => build());

    it('returns paused=true with ledger when contract is paused', async () => {
      const scVal = makeScvMap({ paused: true, paused_at_ledger: 12345 });
      mockSimulate(scVal);

      const result = await service.getPauseState();
      expect(result.paused).toBe(true);
      expect(result.pausedAtLedger).toBe(12345);
    });

    it('returns paused=false with null ledger when not paused', async () => {
      const scVal = makeScvMap({ paused: false });
      mockSimulate(scVal);

      const result = await service.getPauseState();
      expect(result.paused).toBe(false);
      expect(result.pausedAtLedger).toBeNull();
    });

    it('falls back to paused=false on RPC error', async () => {
      mockSimulateError('Network error');
      const result = await service.getPauseState();
      expect(result.paused).toBe(false);
    });

    it('returns paused=false when contract ID is not configured', async () => {
      await build({ QUICKEX_CONTRACT_ID: undefined });
      const result = await service.getPauseState();
      expect(result.paused).toBe(false);
    });
  });

  // ── getContractMetadata ───────────────────────────────────────────────────

  describe('getContractMetadata()', () => {
    beforeEach(() => build());

    it('returns metadata including network and contractId', async () => {
      const scVal = makeScvMap({
        name:               'QuickEx',
        version:            '1.0.0',
        deployed_at_ledger: 9999,
      });
      mockSimulate(scVal);

      const result = await service.getContractMetadata();
      expect(result.network).toBe('testnet');
      expect(result.contractId).toBeTruthy();
      expect(result.name).toBe('QuickEx');
      expect(result.deployedAtLedger).toBe(9999);
    });

    it('returns base defaults on simulation failure', async () => {
      mockSimulateError('not found');
      const result = await service.getContractMetadata();
      expect(result.network).toBe('testnet');
      expect(result.name).toBe('QuickEx Payment Contract');
    });
  });

  // ── getEscrowSummary ──────────────────────────────────────────────────────

  describe('getEscrowSummary()', () => {
    beforeEach(() => build());

    it('returns parsed escrow summary', async () => {
      const scVal = makeScvMap({
        depositor:      'GDEPOSITOR0000000000000000000000000000000000000000000000001',
        beneficiary:    'GBENEFICIARY000000000000000000000000000000000000000000000001',
        amount:         '100',
        asset_code:     'XLM',
        released:       false,
        refunded:       false,
        expiry_ledger:  500,
      });
      mockSimulate(scVal);

      const result = await service.getEscrowSummary('escrow-1');
      expect(result.id).toBe('escrow-1');
      expect(result.depositor).toBe('GDEPOSITOR0000000000000000000000000000000000000000000000001');
      expect(result.amount).toBe('100');
      expect(result.assetCode).toBe('XLM');
      expect(result.released).toBe(false);
      expect(result.expiryLedger).toBe(500);
    });

    it('throws NotFoundException when contract returns null (record missing/TTL lapsed)', async () => {
      mockSimulate(null);
      await expect(service.getEscrowSummary('missing-id'))
        .rejects
        .toBeInstanceOf(NotFoundException);
    });

    it('NotFoundException has ESCROW_NOT_FOUND error code', async () => {
      mockSimulate(null);
      try {
        await service.getEscrowSummary('missing-id');
      } catch (e) {
        expect((e as NotFoundException).getResponse()).toMatchObject({
          error: 'ESCROW_NOT_FOUND',
        });
      }
    });

    it('throws NotFoundException when QUICKEX_CONTRACT_ID is not configured', async () => {
      await build({ QUICKEX_CONTRACT_ID: undefined });
      await expect(service.getEscrowSummary('any'))
        .rejects
        .toBeInstanceOf(NotFoundException);
    });
  });

  // ── getLinkSummary ────────────────────────────────────────────────────────

  describe('getLinkSummary()', () => {
    beforeEach(() => build());

    it('returns parsed link summary', async () => {
      const scVal = makeScvMap({
        id:               'link-abc',
        recipient_address: 'GRECIPIENT00000000000000000000000000000000000000000000000001',
        asset_code:       'USDC',
        amount:           '50',
        active:           true,
        expires_at_ledger: 9999,
      });
      mockSimulate(scVal);

      const result = await service.getLinkSummary('my-slug');
      expect(result.slug).toBe('my-slug');
      expect(result.assetCode).toBe('USDC');
      expect(result.amount).toBe('50');
      expect(result.active).toBe(true);
      expect(result.expiresAtLedger).toBe(9999);
    });

    it('returns expiresAtLedger=null when field is absent', async () => {
      const scVal = makeScvMap({
        id:               'link-no-ttl',
        recipient_address: 'GRECIPIENT00000000000000000000000000000000000000000000000001',
        asset_code:       'XLM',
        amount:           '10',
        active:           true,
        // No expires_at_ledger field
      });
      mockSimulate(scVal);

      const result = await service.getLinkSummary('no-ttl-slug');
      expect(result.expiresAtLedger).toBeNull();
    });

    it('throws NotFoundException for missing link', async () => {
      mockSimulate(null);
      await expect(service.getLinkSummary('ghost-link'))
        .rejects
        .toBeInstanceOf(NotFoundException);
    });

    it('NotFoundException has LINK_NOT_FOUND error code', async () => {
      mockSimulate(null);
      try {
        await service.getLinkSummary('ghost-link');
      } catch (e) {
        expect((e as NotFoundException).getResponse()).toMatchObject({
          error: 'LINK_NOT_FOUND',
        });
      }
    });

    it('caches results — second call does not re-simulate', async () => {
      const scVal = makeScvMap({
        id: 'link-x', recipient_address: 'GX', asset_code: 'XLM',
        amount: '1', active: true,
      });
      mockSimulate(scVal);

      await service.getLinkSummary('slug-x');
      await service.getLinkSummary('slug-x');
      expect(simulateMock).toHaveBeenCalledTimes(1);
    });
  });

  // ── determinism / no data leakage ─────────────────────────────────────────

  describe('access safety', () => {
    beforeEach(() => build());

    it('does not expose admin/privileged fields in FeeConfigView', async () => {
      mockSimulate(makeScvMap({ fee_bps: 50, fee_recipient: '', min_fee_stroops: '0' }));
      const result = await service.getFeeConfig();
      // Ensure no secret-key-adjacent fields sneak into the response
      const keys = Object.keys(result);
      expect(keys).not.toContain('secretKey');
      expect(keys).not.toContain('serviceRoleKey');
      expect(keys).not.toContain('supabaseKey');
    });

    it('views are read-only — no state mutation on the service', async () => {
      mockSimulate(makeScvMap({ fee_bps: 100, fee_recipient: '', min_fee_stroops: '0' }));
      const first  = await service.getFeeConfig();

      // Cache hit — should return same value without re-simulating
      const second = await service.getFeeConfig();
      expect(first).toEqual(second);
    });
  });
});