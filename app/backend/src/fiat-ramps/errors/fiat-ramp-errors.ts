/**
 * Typed errors for the SEP-24 anchor handshake (SEP-01 discovery,
 * SEP-10 authentication, SEP-24 interactive initiation).
 *
 * Each error carries stable fields (domain, phase, operation, ...) so
 * controllers and API consumers can map them deterministically to HTTP
 * responses without string matching.
 */

export class AnchorNotFoundError extends Error {
  constructor(
    public readonly domain: string,
    message?: string,
  ) {
    super(
      message ??
        `Anchor "${domain}" could not be discovered. stellar.toml is unreachable, invalid, or missing the required SEP-24/SEP-10 endpoints.`,
    );
    this.name = 'AnchorNotFoundError';
  }
}

/**
 * The requested asset is not listed in the anchor's stellar.toml CURRENCIES.
 *
 * Note: this is distinct from the `UnsupportedAssetError` in
 * `src/config/stellar.config.ts`, which validates assets against QuickEx's
 * own supported-asset list. This error validates against the anchor's
 * declared capabilities.
 */
export class UnsupportedAssetError extends Error {
  constructor(
    public readonly assetCode: string,
    public readonly domain: string,
    message?: string,
  ) {
    super(
      message ?? `Anchor "${domain}" does not support asset "${assetCode}".`,
    );
    this.name = 'UnsupportedAssetError';
  }
}

export type Sep10AuthPhase =
  | 'challenge_request'
  | 'challenge_parse'
  | 'token_exchange';

export class Sep10AuthError extends Error {
  constructor(
    public readonly domain: string,
    public readonly phase: Sep10AuthPhase,
    message?: string,
  ) {
    super(
      message ??
        `SEP-10 authentication with anchor "${domain}" failed during ${phase}.`,
    );
    this.name = 'Sep10AuthError';
  }
}

export class Sep24InitiationError extends Error {
  constructor(
    public readonly domain: string,
    public readonly operation: 'deposit' | 'withdraw',
    message?: string,
  ) {
    super(
      message ??
        `SEP-24 ${operation} initiation with anchor "${domain}" failed.`,
    );
    this.name = 'Sep24InitiationError';
  }
}

/**
 * Backend configuration is insufficient for the handshake (e.g. the Stellar
 * signing keypair is not configured).
 */
export class FiatRampsConfigurationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'FiatRampsConfigurationError';
  }
}
