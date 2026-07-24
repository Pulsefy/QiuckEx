import { BadRequestException } from '@nestjs/common';
import { DeploymentValidationService } from '../deployment-validation.service';
import { AppConfigService } from '../config';

function buildService(network: string = 'testnet') {
  const config = {
    network,
  } as unknown as AppConfigService;

  return new DeploymentValidationService(config);
}

describe('DeploymentValidationService (SC-W7-08)', () => {
  let service: DeploymentValidationService;

  beforeEach(() => {
    service = buildService();
  });

  describe('validateNetworkBinding', () => {
    it('validates correct testnet network and passphrase', () => {
      expect(() =>
        service.validateNetworkBinding('testnet', 'Test SDF Network ; September 2015'),
      ).not.toThrow();
    });

    it('throws on network mismatch', () => {
      expect(() =>
        service.validateNetworkBinding('mainnet', 'Public Global Stellar Network ; September 2015'),
      ).toThrow(BadRequestException);
      expect(() =>
        service.validateNetworkBinding('mainnet', 'Public Global Stellar Network ; September 2015'),
      ).toThrow('Deployment network mismatch: manifest targets \'mainnet\' but backend is configured for \'testnet\'');
    });

    it('throws on passphrase mismatch', () => {
      expect(() =>
        service.validateNetworkBinding('testnet', 'Public Global Stellar Network ; September 2015'),
      ).toThrow(BadRequestException);
      expect(() =>
        service.validateNetworkBinding('testnet', 'Public Global Stellar Network ; September 2015'),
      ).toThrow('Deployment passphrase mismatch');
    });

    it('throws on both network and passphrase mismatch', () => {
      expect(() =>
        service.validateNetworkBinding('mainnet', 'Wrong Passphrase'),
      ).toThrow(BadRequestException);
    });
  });

  describe('validateLedgerSequence', () => {
    it('accepts valid positive ledger sequence', () => {
      expect(() => service.validateLedgerSequence(47000000)).not.toThrow();
    });

    it('accepts zero for testnet', () => {
      expect(() => service.validateLedgerSequence(0)).not.toThrow();
    });

    it('rejects negative ledger sequence', () => {
      expect(() => service.validateLedgerSequence(-1)).toThrow(BadRequestException);
      expect(() => service.validateLedgerSequence(-1)).toThrow('Invalid ledger sequence');
    });

    it('rejects non-integer ledger sequence', () => {
      expect(() => service.validateLedgerSequence(47000000.5)).toThrow(BadRequestException);
    });

    it('rejects zero for mainnet when configured for mainnet', () => {
      const mainnetService = buildService('mainnet');

      expect(() => mainnetService.validateLedgerSequence(0)).toThrow(BadRequestException);
      expect(() => mainnetService.validateLedgerSequence(0)).toThrow(
        'Invalid ledger sequence for mainnet deployment',
      );
    });
  });

  describe('validateDeploymentManifest', () => {
    it('validates complete manifest with ledger sequence', () => {
      const manifest = {
        network: 'testnet',
        network_passphrase: 'Test SDF Network ; September 2015',
        ledger_sequence: 47000000,
      };

      expect(() => service.validateDeploymentManifest(manifest)).not.toThrow();
    });

    it('validates manifest without ledger sequence (with warning)', () => {
      const manifest = {
        network: 'testnet',
        network_passphrase: 'Test SDF Network ; September 2015',
      };

      expect(() => service.validateDeploymentManifest(manifest)).not.toThrow();
    });

    it('throws on network mismatch in manifest', () => {
      const manifest = {
        network: 'mainnet',
        network_passphrase: 'Public Global Stellar Network ; September 2015',
        ledger_sequence: 47000000,
      };

      expect(() => service.validateDeploymentManifest(manifest)).toThrow(BadRequestException);
    });

    it('throws on invalid ledger sequence in manifest', () => {
      const manifest = {
        network: 'testnet',
        network_passphrase: 'Test SDF Network ; September 2015',
        ledger_sequence: -1,
      };

      expect(() => service.validateDeploymentManifest(manifest)).toThrow(BadRequestException);
    });

    it('throws on passphrase mismatch in manifest', () => {
      const manifest = {
        network: 'testnet',
        network_passphrase: 'Wrong Passphrase',
        ledger_sequence: 47000000,
      };

      expect(() => service.validateDeploymentManifest(manifest)).toThrow(BadRequestException);
    });
  });

  describe('checkNetworkCompatibility', () => {
    it('returns compatible for matching network and passphrase', () => {
      const result = service.checkNetworkCompatibility(
        'testnet',
        'Test SDF Network ; September 2015',
      );

      expect(result.compatible).toBe(true);
      expect(result.activeNetwork).toBe('testnet');
      expect(result.reason).toBeUndefined();
    });

    it('returns incompatible for network mismatch', () => {
      const result = service.checkNetworkCompatibility(
        'mainnet',
        'Public Global Stellar Network ; September 2015',
      );

      expect(result.compatible).toBe(false);
      expect(result.activeNetwork).toBe('testnet');
      expect(result.reason).toContain('Network mismatch');
    });

    it('returns incompatible for passphrase mismatch', () => {
      const result = service.checkNetworkCompatibility('testnet', 'Wrong Passphrase');

      expect(result.compatible).toBe(false);
      expect(result.activeNetwork).toBe('testnet');
      expect(result.reason).toContain('Passphrase mismatch');
    });
  });

  describe('getExpectedPassphrase', () => {
    it('returns correct passphrase for testnet', () => {
      const passphrase = service.getExpectedPassphrase('testnet');
      expect(passphrase).toBe('Test SDF Network ; September 2015');
    });

    it('returns correct passphrase for mainnet', () => {
      const passphrase = service.getExpectedPassphrase('mainnet');
      expect(passphrase).toBe('Public Global Stellar Network ; September 2015');
    });

    it('throws for invalid network', () => {
      expect(() => service.getExpectedPassphrase('invalid')).toThrow(BadRequestException);
      expect(() => service.getExpectedPassphrase('invalid')).toThrow('Invalid network');
    });
  });

  describe('mismatched network/deployment scenarios', () => {
    it('detects testnet deployment on mainnet backend', () => {
      const mainnetService = buildService('mainnet');

      const testnetManifest = {
        network: 'testnet',
        network_passphrase: 'Test SDF Network ; September 2015',
        ledger_sequence: 47000000,
      };

      expect(() => mainnetService.validateDeploymentManifest(testnetManifest)).toThrow(
        BadRequestException,
      );
      expect(() => mainnetService.validateDeploymentManifest(testnetManifest)).toThrow(
        'Deployment network mismatch',
      );
    });

    it('detects mainnet deployment on testnet backend', () => {
      const mainnetManifest = {
        network: 'mainnet',
        network_passphrase: 'Public Global Stellar Network ; September 2015',
        ledger_sequence: 50000000,
      };

      expect(() => service.validateDeploymentManifest(mainnetManifest)).toThrow(BadRequestException);
      expect(() => service.validateDeploymentManifest(mainnetManifest)).toThrow(
        'Deployment network mismatch',
      );
    });

    it('detects cross-network passphrase confusion', () => {
      // Testnet network with mainnet passphrase
      const confusedManifest = {
        network: 'testnet',
        network_passphrase: 'Public Global Stellar Network ; September 2015',
        ledger_sequence: 47000000,
      };

      expect(() => service.validateDeploymentManifest(confusedManifest)).toThrow(BadRequestException);
      expect(() => service.validateDeploymentManifest(confusedManifest)).toThrow(
        'Deployment passphrase mismatch',
      );
    });

    it('detects stale deployment with very old ledger sequence', () => {
      const oldManifest = {
        network: 'testnet',
        network_passphrase: 'Test SDF Network ; September 2015',
        ledger_sequence: 1000, // Very old ledger
      };

      // This should not throw on ledger sequence alone (age check is optional)
      expect(() => service.validateDeploymentManifest(oldManifest)).not.toThrow();
    });
  });
});
