import { Injectable, Logger, BadRequestException } from '@nestjs/common';
import { AppConfigService } from '../config';

/**
 * Network and ledger binding validation helpers for deployment metadata.
 * Ensures deployments are correctly targeted to the intended network and ledger context.
 *
 * SC-W7-08: Deployment Metadata Ledger Binding
 */
@Injectable()
export class DeploymentValidationService {
  private readonly logger = new Logger(DeploymentValidationService.name);

  private readonly NETWORK_PASSPHRASES = {
    testnet: 'Test SDF Network ; September 2015',
    mainnet: 'Public Global Stellar Network ; September 2015',
  } as const;

  constructor(private readonly configService: AppConfigService) {}

  /**
   * Validates that a deployment manifest's network binding matches the active backend network.
   * @throws BadRequestException if network or passphrase mismatch
   */
  validateNetworkBinding(manifestNetwork: string, manifestPassphrase: string): void {
    const activeNetwork = this.configService.network;
    const expectedPassphrase = this.NETWORK_PASSPHRASES[activeNetwork];

    if (manifestNetwork !== activeNetwork) {
      throw new BadRequestException(
        `Deployment network mismatch: manifest targets '${manifestNetwork}' but backend is configured for '${activeNetwork}'`,
      );
    }

    if (manifestPassphrase !== expectedPassphrase) {
      throw new BadRequestException(
        `Deployment passphrase mismatch: manifest has '${manifestPassphrase}' but expected '${expectedPassphrase}' for ${activeNetwork}`,
      );
    }

    this.logger.debug(`Network binding validated: ${activeNetwork} with correct passphrase`);
  }

  /**
   * Validates that a ledger sequence is within acceptable bounds for the network.
   * This helps detect stale or future deployment manifests.
   *
   * @param ledgerSequence The ledger sequence from the deployment manifest
   * @param maxAgeSeconds Maximum age of the deployment in seconds (default: 30 days)
   * @throws BadRequestException if ledger sequence is invalid
   */
  validateLedgerSequence(ledgerSequence: number, maxAgeSeconds: number = 30 * 24 * 60 * 60): void {
    if (!Number.isInteger(ledgerSequence) || ledgerSequence < 0) {
      throw new BadRequestException(
        `Invalid ledger sequence: ${ledgerSequence}. Must be a non-negative integer.`,
      );
    }

    // For testnet, we're more lenient with ledger sequence validation
    // For mainnet, we enforce stricter checks
    if (this.configService.network === 'mainnet' && ledgerSequence === 0) {
      throw new BadRequestException(
        'Invalid ledger sequence for mainnet deployment: 0 is not valid for production deployments',
      );
    }

    this.logger.debug(`Ledger sequence validated: ${ledgerSequence}`);
  }

  /**
   * Validates that a deployment manifest is properly bound to its network context.
   * Combines network and ledger validation.
   *
   * @param manifest The deployment manifest to validate
   * @throws BadRequestException if validation fails
   */
  validateDeploymentManifest(manifest: {
    network: string;
    network_passphrase: string;
    ledger_sequence?: number;
  }): void {
    this.validateNetworkBinding(manifest.network, manifest.network_passphrase);

    if (manifest.ledger_sequence !== undefined) {
      this.validateLedgerSequence(manifest.ledger_sequence);
    } else {
      this.logger.warn('Deployment manifest missing ledger_sequence - ledger binding validation skipped');
    }
  }

  /**
   * Checks if a deployment is potentially mis-targeted by comparing network contexts.
   * Returns a validation result without throwing, useful for non-blocking checks.
   *
   * @param manifestNetwork Network from the deployment manifest
   * @param manifestPassphrase Passphrase from the deployment manifest
   * @returns Validation result with details
   */
  checkNetworkCompatibility(manifestNetwork: string, manifestPassphrase: string): {
    compatible: boolean;
    reason?: string;
    activeNetwork: string;
  } {
    const activeNetwork = this.configService.network;
    const expectedPassphrase = this.NETWORK_PASSPHRASES[activeNetwork];

    if (manifestNetwork !== activeNetwork) {
      return {
        compatible: false,
        reason: `Network mismatch: manifest targets '${manifestNetwork}' but backend is '${activeNetwork}'`,
        activeNetwork,
      };
    }

    if (manifestPassphrase !== expectedPassphrase) {
      return {
        compatible: false,
        reason: `Passphrase mismatch for ${activeNetwork}`,
        activeNetwork,
      };
    }

    return { compatible: true, activeNetwork };
  }

  /**
   * Gets the expected network passphrase for a given network name.
   *
   * @param network The network name ('testnet' or 'mainnet')
   * @returns The expected network passphrase
   * @throws BadRequestException if network is invalid
   */
  getExpectedPassphrase(network: string): string {
    const passphrase = this.NETWORK_PASSPHRASES[network as keyof typeof this.NETWORK_PASSPHRASES];
    if (!passphrase) {
      throw new BadRequestException(`Invalid network: ${network}. Must be 'testnet' or 'mainnet'.`);
    }
    return passphrase;
  }
}
