/**
 * FiatRampsService – Unit Tests
 *
 * Covers:
 *   - Deposit initiation via real SEP-24 handshake (discovery → SEP-10 → initiation)
 *   - Withdrawal initiation via real SEP-24 handshake
 *   - Error handling for unsupported assets, auth failures, unreachable anchors
 *   - Error classification (400 client errors vs 502 auth failures vs 500 internal)
 */

import { Test, TestingModule } from '@nestjs/testing';
import { HttpException } from '@nestjs/common';
import { FiatRampsService } from './fiat-ramps.service';
import { Sep24TransactionRepository } from './sep24-transaction.repository';
import { AnchorClientService } from './anchor-client.service';
import { AppConfigService } from '../config/app-config.service';
import {
  Sep24InternalStatus,
  AnchorDiscoveryError,
  Sep10AuthError,
  Sep24InitiationError,
} from './types/sep24.types';

// ─── Mocks ────────────────────────────────────────────────────────────────────

const mockSep24Repository = {
  create: jest.fn(),
  findByAnchorTransactionId: jest.fn(),
  updateStatus: jest.fn(),
};

const mockAnchorClient = {
  discoverAnchorCapabilities: jest.fn(),
  performSep10Auth: jest.fn(),
  initiateSep24Transaction: jest.fn(),
};

const mockAppConfig = {
  stellarNetworkPassphrase: 'Test SDF Network ; September 2015',
  stellarSecretKey: 'SCX6A3F3XCFW7IT3MY6DSZWULY4U6O5PZHILY3SAPU4QZIHUEO7JZLLS',
};

// ─── Helpers ──────────────────────────────────────────────────────────────────

function mockSuccessFlow() {
  mockAnchorClient.discoverAnchorCapabilities.mockResolvedValue({
    transferServer: 'https://test.anchor.org/sep24',
    authServer: 'https://test.anchor.org/auth',
    supportedAssets: ['USDC', 'EURC', 'XLM'],
  });

  mockAnchorClient.performSep10Auth.mockResolvedValue('fake-jwt-token');

  mockAnchorClient.initiateSep24Transaction.mockResolvedValue({
    type: 'interactive_customer_info_needed',
    url: 'https://test.anchor.org/sep24/interactive/form/abc123',
    id: 'anchor-tx-001',
    message: 'Please complete the form',
  });

  mockSep24Repository.create.mockResolvedValue({
    id: 'uuid-001',
    anchor_transaction_id: 'anchor-tx-001',
  });
}

const DEPOSIT_DTO = {
  assetCode: 'USDC',
  amount: 100,
  userAccount: 'GABC123DEF456',
  anchorDomain: 'test.anchor.org',
};

const WITHDRAWAL_DTO = {
  assetCode: 'EURC',
  amount: 50,
  userAccount: 'GDEF789GHI012',
  anchorDomain: 'test.anchor.org',
};

// ─── Tests ────────────────────────────────────────────────────────────────────

describe('FiatRampsService', () => {
  let service: FiatRampsService;

  beforeEach(async () => {
    jest.clearAllMocks();

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        FiatRampsService,
        { provide: Sep24TransactionRepository, useValue: mockSep24Repository },
        { provide: AnchorClientService, useValue: mockAnchorClient },
        { provide: AppConfigService, useValue: mockAppConfig },
      ],
    }).compile();

    service = module.get<FiatRampsService>(FiatRampsService);
  });

  // ─── getAvailableAnchors ──────────────────────────────────────────────────

  describe('getAvailableAnchors', () => {
    it('returns available anchors for given asset and country', async () => {
      const result = await service.getAvailableAnchors('USDC', 'US');

      expect(result.status).toBe('success');
      expect(result.data).toBeInstanceOf(Array);
      expect(result.data.length).toBeGreaterThan(0);
      expect(result.data[0]).toHaveProperty('domain');
      expect(result.data[0]).toHaveProperty('supportedAssets');
    });
  });

  // ─── initiateDeposit ─────────────────────────────────────────────────────

  describe('initiateDeposit', () => {
    it('performs full SEP-24 handshake and returns interactive URL', async () => {
      mockSuccessFlow();

      const result = await service.initiateDeposit(DEPOSIT_DTO);

      // Verify the three-step handshake was performed
      expect(mockAnchorClient.discoverAnchorCapabilities).toHaveBeenCalledWith('test.anchor.org');
      expect(mockAnchorClient.performSep10Auth).toHaveBeenCalledWith(
        'test.anchor.org',
        'https://test.anchor.org/auth',
        expect.anything(), // Keypair
        'Test SDF Network ; September 2015',
      );
      expect(mockAnchorClient.initiateSep24Transaction).toHaveBeenCalledWith({
        anchorDomain: 'test.anchor.org',
        jwt: 'fake-jwt-token',
        transferServer: 'https://test.anchor.org/sep24',
        type: 'deposit',
        assetCode: 'USDC',
        account: 'GABC123DEF456',
        amount: '100',
      });

      // Verify repository was called to persist the transaction
      expect(mockSep24Repository.create).toHaveBeenCalledWith(
        expect.objectContaining({
          anchor_transaction_id: 'anchor-tx-001',
          anchor_domain: 'test.anchor.org',
          type: 'deposit',
          status: Sep24InternalStatus.Initiated,
          asset_code: 'USDC',
          user_account: 'GABC123DEF456',
          interactive_url: 'https://test.anchor.org/sep24/interactive/form/abc123',
        }),
      );

      // Verify response shape
      expect(result).toEqual({
        status: 'success',
        transaction_id: 'anchor-tx-001',
        internal_id: 'uuid-001',
        type: 'interactive_customer_info_needed',
        url: 'https://test.anchor.org/sep24/interactive/form/abc123',
        message: 'Please complete the form',
      });
    });

    it('throws 400 for unsupported asset', async () => {
      mockAnchorClient.discoverAnchorCapabilities.mockResolvedValue({
        transferServer: 'https://test.anchor.org/sep24',
        authServer: 'https://test.anchor.org/auth',
        supportedAssets: ['USDC', 'EURC'],
      });

      await expect(
        service.initiateDeposit({ ...DEPOSIT_DTO, assetCode: 'XYZ' }),
      ).rejects.toThrow(HttpException);

      // Should NOT have attempted SEP-10 auth
      expect(mockAnchorClient.performSep10Auth).not.toHaveBeenCalled();
    });

    it('throws 400 when anchor discovery fails (unreachable anchor)', async () => {
      mockAnchorClient.discoverAnchorCapabilities.mockRejectedValue(
        new AnchorDiscoveryError('test.anchor.org', 'stellar.toml HTTP 404'),
      );

      await expect(service.initiateDeposit(DEPOSIT_DTO)).rejects.toThrow(HttpException);

      expect(mockAnchorClient.performSep10Auth).not.toHaveBeenCalled();
      expect(mockAnchorClient.initiateSep24Transaction).not.toHaveBeenCalled();
    });

    it('throws 502 when SEP-10 authentication fails', async () => {
      mockAnchorClient.discoverAnchorCapabilities.mockResolvedValue({
        transferServer: 'https://test.anchor.org/sep24',
        authServer: 'https://test.anchor.org/auth',
        supportedAssets: ['USDC'],
      });

      mockAnchorClient.performSep10Auth.mockRejectedValue(
        new Sep10AuthError('test.anchor.org', 'challenge request failed: HTTP 401'),
      );

      try {
        await service.initiateDeposit(DEPOSIT_DTO);
        fail('should have thrown');
      } catch (error) {
        expect(error).toBeInstanceOf(HttpException);
        expect((error as HttpException).getStatus()).toBe(502);
      }
    });

    it('throws 400 when SEP-24 initiation fails (anchor rejects request)', async () => {
      mockAnchorClient.discoverAnchorCapabilities.mockResolvedValue({
        transferServer: 'https://test.anchor.org/sep24',
        authServer: 'https://test.anchor.org/auth',
        supportedAssets: ['USDC'],
      });

      mockAnchorClient.performSep10Auth.mockResolvedValue('jwt-token');

      mockAnchorClient.initiateSep24Transaction.mockRejectedValue(
        new Sep24InitiationError('test.anchor.org', 'unsupported asset or bad request — HTTP 400', 400),
      );

      try {
        await service.initiateDeposit(DEPOSIT_DTO);
        fail('should have thrown');
      } catch (error) {
        expect(error).toBeInstanceOf(HttpException);
        expect((error as HttpException).getStatus()).toBe(400);
      }
    });

    it('throws 500 for unexpected internal errors', async () => {
      mockAnchorClient.discoverAnchorCapabilities.mockRejectedValue(
        new Error('unexpected error'),
      );

      try {
        await service.initiateDeposit(DEPOSIT_DTO);
        fail('should have thrown');
      } catch (error) {
        expect(error).toBeInstanceOf(HttpException);
        expect((error as HttpException).getStatus()).toBe(500);
      }
    });

    it('generates placeholder ID when anchor does not return one', async () => {
      mockSuccessFlow();
      mockAnchorClient.initiateSep24Transaction.mockResolvedValue({
        type: 'interactive_customer_info_needed',
        url: 'https://test.anchor.org/sep24/interactive/form/xyz',
        // no id field
      });
      mockSep24Repository.create.mockResolvedValue({ id: 'uuid-002', anchor_transaction_id: 'dep_1234567890' });

      const result = await service.initiateDeposit(DEPOSIT_DTO);

      expect(result.transaction_id).toMatch(/^dep_/);
    });

    it('normalizes assetCode to uppercase', async () => {
      mockSuccessFlow();

      await service.initiateDeposit({ ...DEPOSIT_DTO, assetCode: 'usdc' });

      expect(mockAnchorClient.initiateSep24Transaction).toHaveBeenCalledWith(
        expect.objectContaining({ assetCode: 'USDC' }),
      );
      expect(mockSep24Repository.create).toHaveBeenCalledWith(
        expect.objectContaining({ asset_code: 'USDC' }),
      );
    });

    it('omits message from response when anchor does not provide one', async () => {
      mockSuccessFlow();
      mockAnchorClient.initiateSep24Transaction.mockResolvedValue({
        type: 'interactive_customer_info_needed',
        url: 'https://test.anchor.org/sep24/interactive/form/nomsg',
        id: 'anchor-tx-002',
        // no message
      });
      mockSep24Repository.create.mockResolvedValue({ id: 'uuid-003', anchor_transaction_id: 'anchor-tx-002' });

      const result = await service.initiateDeposit(DEPOSIT_DTO);

      expect(result).not.toHaveProperty('message');
    });
  });

  // ─── initiateWithdrawal ───────────────────────────────────────────────────

  describe('initiateWithdrawal', () => {
    it('performs full SEP-24 handshake and returns interactive URL', async () => {
      mockSuccessFlow();

      const result = await service.initiateWithdrawal(WITHDRAWAL_DTO);

      // Verify the three-step handshake
      expect(mockAnchorClient.discoverAnchorCapabilities).toHaveBeenCalledWith('test.anchor.org');
      expect(mockAnchorClient.performSep10Auth).toHaveBeenCalled();
      expect(mockAnchorClient.initiateSep24Transaction).toHaveBeenCalledWith({
        anchorDomain: 'test.anchor.org',
        jwt: 'fake-jwt-token',
        transferServer: 'https://test.anchor.org/sep24',
        type: 'withdrawal',
        assetCode: 'EURC',
        account: 'GDEF789GHI012',
        amount: '50',
      });

      expect(mockSep24Repository.create).toHaveBeenCalledWith(
        expect.objectContaining({
          type: 'withdrawal',
          asset_code: 'EURC',
          interactive_url: 'https://test.anchor.org/sep24/interactive/form/abc123',
        }),
      );

      expect(result).toEqual({
        status: 'success',
        transaction_id: 'anchor-tx-001',
        internal_id: 'uuid-001',
        type: 'interactive_customer_info_needed',
        url: 'https://test.anchor.org/sep24/interactive/form/abc123',
        message: 'Please complete the form',
      });
    });

    it('throws 400 for unsupported asset', async () => {
      mockAnchorClient.discoverAnchorCapabilities.mockResolvedValue({
        transferServer: 'https://test.anchor.org/sep24',
        authServer: 'https://test.anchor.org/auth',
        supportedAssets: ['USDC'],
      });

      await expect(
        service.initiateWithdrawal({ ...WITHDRAWAL_DTO, assetCode: 'EURC' }),
      ).rejects.toThrow(HttpException);
    });

    it('throws 400 when anchor discovery fails', async () => {
      mockAnchorClient.discoverAnchorCapabilities.mockRejectedValue(
        new AnchorDiscoveryError('test.anchor.org', 'network error'),
      );

      await expect(service.initiateWithdrawal(WITHDRAWAL_DTO)).rejects.toThrow(HttpException);
    });

    it('throws 502 when SEP-10 auth fails', async () => {
      mockAnchorClient.discoverAnchorCapabilities.mockResolvedValue({
        transferServer: 'https://test.anchor.org/sep24',
        authServer: 'https://test.anchor.org/auth',
        supportedAssets: ['EURC'],
      });

      mockAnchorClient.performSep10Auth.mockRejectedValue(
        new Sep10AuthError('test.anchor.org', 'invalid signature'),
      );

      try {
        await service.initiateWithdrawal(WITHDRAWAL_DTO);
        fail('should have thrown');
      } catch (error) {
        expect(error).toBeInstanceOf(HttpException);
        expect((error as HttpException).getStatus()).toBe(502);
      }
    });

    it('throws 400 when SEP-24 initiation fails', async () => {
      mockAnchorClient.discoverAnchorCapabilities.mockResolvedValue({
        transferServer: 'https://test.anchor.org/sep24',
        authServer: 'https://test.anchor.org/auth',
        supportedAssets: ['EURC'],
      });

      mockAnchorClient.performSep10Auth.mockResolvedValue('jwt-token');
      mockAnchorClient.initiateSep24Transaction.mockRejectedValue(
        new Sep24InitiationError('test.anchor.org', 'anchor error'),
      );

      try {
        await service.initiateWithdrawal(WITHDRAWAL_DTO);
        fail('should have thrown');
      } catch (error) {
        expect(error).toBeInstanceOf(HttpException);
        expect((error as HttpException).getStatus()).toBe(400);
      }
    });

    it('generates placeholder ID when anchor does not return one', async () => {
      mockSuccessFlow();
      mockAnchorClient.initiateSep24Transaction.mockResolvedValue({
        type: 'interactive_customer_info_needed',
        url: 'https://test.anchor.org/sep24/interactive/form/abc123',
      });
      mockSep24Repository.create.mockResolvedValue({ id: 'uuid-004', anchor_transaction_id: 'wth_1234567890' });

      const result = await service.initiateWithdrawal(WITHDRAWAL_DTO);

      expect(result.transaction_id).toMatch(/^wth_/);
    });
  });

  // ─── handleKycCallback ───────────────────────────────────────────────────

  describe('handleKycCallback', () => {
    it('returns acknowledged for KYC callback data', async () => {
      const result = await service.handleKycCallback({ status: 'approved' });
      expect(result).toEqual({ status: 'acknowledged' });
    });
  });

  // ─── updateTransactionStatus ─────────────────────────────────────────────

  describe('updateTransactionStatus', () => {
    it('returns acknowledged for status update data', async () => {
      mockSep24Repository.findByAnchorTransactionId.mockResolvedValue(null);

      const result = await service.updateTransactionStatus({ id: 'tx-1', status: 'completed' });
      expect(result).toEqual({ status: 'acknowledged' });
    });

    it('updates existing transaction record when anchor ID matches', async () => {
      const existingRecord = {
        id: 'uuid-existing',
        anchor_transaction_id: 'anchor-tx-999',
        stellar_tx_hash: null,
      };

      mockSep24Repository.findByAnchorTransactionId.mockResolvedValue(existingRecord);
      mockSep24Repository.updateStatus.mockResolvedValue(undefined);

      await service.updateTransactionStatus({
        id: 'anchor-tx-999',
        status: 'completed',
        stellar_transaction_id: 'stellar-hash-123',
      });

      expect(mockSep24Repository.updateStatus).toHaveBeenCalledWith(
        'uuid-existing',
        'completed',
        'completed',
        'stellar-hash-123',
      );
    });
  });
});
