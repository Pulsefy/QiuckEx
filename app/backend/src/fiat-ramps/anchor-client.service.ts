/**
 * Anchor Client Service
 *
 * Thin HTTP client for SEP-24 anchor interactions.  Provides:
 *
 *   1. **Capability discovery** — fetches and parses the anchor's `stellar.toml`
 *      to discover the SEP-10 auth server and SEP-24 transfer server URLs.
 *   2. **SEP-10 authentication** — performs the full challenge-response flow to
 *      obtain a signed JWT.
 *   3. **SEP-24 initiation** — POSTs to the anchor's interactive endpoint and
 *      returns the real interactive URL negotiated by the anchor.
 *   4. **Transaction polling** — GETs transaction status for the polling service.
 *
 * Retry / backoff for polling is intentionally left to the caller (the polling
 * service tracks per-transaction failure counts so it can apply graduated
 * backoff without blocking the whole poll cycle).
 */

import { Injectable, Logger } from '@nestjs/common';
import { Keypair, TransactionBuilder } from '@stellar/stellar-sdk';
import {
  AnchorCapabilities,
  AnchorTransactionResponse,
  AnchorDiscoveryError,
  Sep10AuthError,
  Sep24InitiationError,
  Sep24InteractiveResponse,
} from './types/sep24.types';

// ─── Poll types (unchanged from original) ────────────────────────────────────

/** Options for polling a single anchor transaction. */
export interface AnchorPollOptions {
  /** Anchor domain (e.g. "moneygram.stellar.org"). */
  anchorDomain: string;
  /** SEP-24 transaction id assigned by the anchor. */
  transactionId: string;
  /**
   * Optional JWT obtained via SEP-10 authentication.
   * When absent the endpoint is still called — some anchors allow
   * unauthenticated status polling.
   */
  jwt?: string;
}

/** Result of an anchor poll attempt. */
export interface AnchorPollResult {
  success: boolean;
  data: AnchorTransactionResponse | null;
  /** HTTP status code, or null on network error. */
  httpStatus: number | null;
  /** Error message when success === false. */
  error: string | null;
}

// ─── SEP-24 initiation options ───────────────────────────────────────────────

/** Parameters for initiating a SEP-24 deposit or withdrawal. */
export interface Sep24InitiateOptions {
  /** Anchor domain (e.g. "moneygram.stellar.org"). */
  anchorDomain: string;
  /** SEP-10 JWT obtained via {@link performSep10Auth}. */
  jwt: string;
  /** Transfer server URL (from {@link discoverAnchorCapabilities}). */
  transferServer: string;
  /** "deposit" or "withdrawal". */
  type: 'deposit' | 'withdrawal';
  /** Asset code (e.g. "USDC"). */
  assetCode: string;
  /** Stellar public key of the user initiating the flow. */
  account: string;
  /** Amount as a decimal string (e.g. "100.00"). */
  amount?: string;
  /** Optional: non-native asset issuer public key. */
  assetIssuer?: string;
  /** Optional: URL the anchor can redirect the user back to on completion. */
  returnUrl?: string;
  /** Optional: arbitrary data passed through to the anchor. */
  memo?: string;
  /** Optional: memo type ("text" | "id" | "hash"). */
  memoType?: string;
}

@Injectable()
export class AnchorClientService {
  private readonly logger = new Logger(AnchorClientService.name);

  // ─── Capability Discovery ────────────────────────────────────────────────

  /**
   * Fetch the anchor's `stellar.toml` and extract the SEP-10 auth server,
   * SEP-24 transfer server, and the list of supported asset codes.
   *
   * @throws {AnchorDiscoveryError} when the TOML is unreachable or missing
   *         required fields.
   */
  async discoverAnchorCapabilities(anchorDomain: string): Promise<AnchorCapabilities> {
    const cleanDomain = anchorDomain.replace(/^https?:\/\//, '').replace(/\/$/, '');
    const tomlUrl = `https://${cleanDomain}/.well-known/stellar.toml`;

    let text: string;

    try {
      const response = await fetch(tomlUrl, {
        method: 'GET',
        headers: { Accept: 'text/plain, application/toml' },
        signal: AbortSignal.timeout(8_000),
      });

      if (!response.ok) {
        throw new AnchorDiscoveryError(
          anchorDomain,
          `stellar.toml HTTP ${response.status} from ${tomlUrl}`,
        );
      }

      text = await response.text();
    } catch (err) {
      if (err instanceof AnchorDiscoveryError) throw err;
      const message = err instanceof Error ? err.message : String(err);
      throw new AnchorDiscoveryError(anchorDomain, `network error fetching ${tomlUrl}: ${message}`);
    }

    // ── Parse required fields ────────────────────────────────────────────────

    const transferServerMatch = text.match(
      /TRANSFER_SERVER_SEP0024\s*=\s*["']([^"']+)["']/,
    );
    if (!transferServerMatch) {
      throw new AnchorDiscoveryError(
        anchorDomain,
        'stellar.toml missing TRANSFER_SERVER_SEP0024',
      );
    }

    const authServerMatch = text.match(
      /TRANSFER_SERVER_SEP0010\s*=\s*["']([^"']+)["']/,
    );
    if (!authServerMatch) {
      throw new AnchorDiscoveryError(
        anchorDomain,
        'stellar.toml missing TRANSFER_SERVER_SEP0010',
      );
    }

    // ── Parse supported assets (optional but useful) ─────────────────────────

    const supportedAssets: string[] = [];

    // Match [[CURRENCIES]] / code = "..." blocks
    const codeMatches = text.matchAll(/code\s*=\s*["']([A-Z0-9]+)["']/g);
    for (const m of codeMatches) {
      const code = m[1];
      if (!supportedAssets.includes(code)) {
        supportedAssets.push(code);
      }
    }

    this.logger.debug(
      `Discovered anchor capabilities for ${anchorDomain}: ` +
      `transferServer=${transferServerMatch[1]}, ` +
      `authServer=${authServerMatch[1]}, ` +
      `assets=[${supportedAssets.join(', ')}]`,
    );

    return {
      transferServer: transferServerMatch[1],
      authServer: authServerMatch[1],
      supportedAssets,
    };
  }

  // ─── SEP-10 Authentication ───────────────────────────────────────────────

  /**
   * Perform a full SEP-10 challenge-response authentication flow against
   * the anchor's auth server.
   *
   * Steps:
   *   1. POST `{"account": "<publicKey>"}` to `{authServer}/auth`
   *   2. Receive a challenge transaction envelope XDR + network passphrase
   *   3. Sign the transaction with the provided keypair
   *   4. POST `{"transaction": "<signedEnvelopeXdr>", "account": "<publicKey>"}` back
   *   5. Receive the JWT token
   *
   * @param anchorDomain   - Human-readable anchor domain for logging.
   * @param authServer     - Full auth server URL (from {@link discoverAnchorCapabilities}).
   * @param keypair        - Stellar Keypair to sign the challenge.
   * @param networkPassphrase - Stellar network passphrase (e.g. "Test SDF Network ; September 2015").
   * @returns The signed JWT string.
   * @throws {Sep10AuthError} on any failure during the flow.
   */
  async performSep10Auth(
    anchorDomain: string,
    authServer: string,
    keypair: Keypair,
    networkPassphrase: string,
  ): Promise<string> {
    const cleanAuthServer = authServer.replace(/\/$/, '');

    // ── Step 1: Request challenge ─────────────────────────────────────────────

    // The TRANSFER_SERVER_SEP0010 value from stellar.toml is the auth endpoint.
    // Use it directly — do not append /auth (real anchors include it in the URL).
    const challengeUrl = `${cleanAuthServer}`;
    const publicKey = keypair.publicKey();

    let challengeBody: { transaction: string; network_passphrase: string };

    try {
      const challengeResponse = await fetch(challengeUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json',
        },
        body: JSON.stringify({ account: publicKey }),
        signal: AbortSignal.timeout(10_000),
      });

      if (!challengeResponse.ok) {
        const errText = await challengeResponse.text().catch(() => '');
        throw new Sep10AuthError(
          anchorDomain,
          `challenge request failed: HTTP ${challengeResponse.status} — ${errText}`,
          challengeResponse.status,
        );
      }

      challengeBody = await challengeResponse.json() as {
        transaction: string;
        network_passphrase: string;
      };

      if (!challengeBody?.transaction) {
        throw new Sep10AuthError(anchorDomain, 'challenge response missing transaction field');
      }
    } catch (err) {
      if (err instanceof Sep10AuthError) throw err;
      const message = err instanceof Error ? err.message : String(err);
      throw new Sep10AuthError(anchorDomain, `network error during challenge: ${message}`);
    }

    // ── Step 2: Sign the challenge transaction ────────────────────────────────

    let signedEnvelopeXdr: string;

    try {
      const txOrFeeBump = TransactionBuilder.fromXDR(
        challengeBody.transaction,
        challengeBody.network_passphrase || networkPassphrase,
      );

      // fromXDR returns Transaction | FeeBumpTransaction;
      // both extend TransactionI which has .sign() and .toXDR().
      txOrFeeBump.sign(keypair);
      signedEnvelopeXdr = txOrFeeBump.toXDR();
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      throw new Sep10AuthError(anchorDomain, `failed to sign challenge transaction: ${message}`);
    }

    // ── Step 3: Submit signed challenge ───────────────────────────────────────

    let authResult: { token: string };

    try {
      const submitResponse = await fetch(challengeUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json',
        },
        body: JSON.stringify({
          transaction: signedEnvelopeXdr,
          account: publicKey,
        }),
        signal: AbortSignal.timeout(10_000),
      });

      if (!submitResponse.ok) {
        const errText = await submitResponse.text().catch(() => '');
        throw new Sep10AuthError(
          anchorDomain,
          `auth submission failed: HTTP ${submitResponse.status} — ${errText}`,
          submitResponse.status,
        );
      }

      authResult = await submitResponse.json() as { token: string };

      if (!authResult?.token) {
        throw new Sep10AuthError(anchorDomain, 'auth response missing token field');
      }
    } catch (err) {
      if (err instanceof Sep10AuthError) throw err;
      const message = err instanceof Error ? err.message : String(err);
      throw new Sep10AuthError(anchorDomain, `network error during auth submission: ${message}`);
    }

    this.logger.debug(`SEP-10 auth succeeded for ${anchorDomain}`);

    return authResult.token;
  }

  // ─── SEP-24 Transaction Initiation ──────────────────────────────────────

  /**
   * Initiate a SEP-24 hosted-interactive deposit or withdrawal transaction.
   *
   * POSTs to `{transferServer}/transactions/{type}/interactive` with the
   * SEP-10 JWT and returns the anchor's interactive URL.
   *
   * @throws {Sep24InitiationError} when the anchor rejects the request or
   *         returns an unexpected response.
   */
  async initiateSep24Transaction(opts: Sep24InitiateOptions): Promise<Sep24InteractiveResponse> {
    const {
      anchorDomain,
      jwt,
      transferServer,
      type,
      assetCode,
      account,
      amount,
      assetIssuer,
      returnUrl,
      memo,
      memoType,
    } = opts;

    const cleanTransferServer = transferServer.replace(/\/$/, '');
    const endpointUrl = `${cleanTransferServer}/transactions/${type}/interactive`;

    // ── Build request body ──────────────────────────────────────────────────

    const body: Record<string, string> = {
      asset_code: assetCode,
      account,
    };

    if (amount) body.amount = amount;
    if (assetIssuer) body.asset_issuer = assetIssuer;
    if (returnUrl) body.return_url = returnUrl;
    if (memo) body.memo = memo;
    if (memoType) body.memo_type = memoType;

    // ── POST to anchor ──────────────────────────────────────────────────────

    let response: Response;

    try {
      response = await fetch(endpointUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${jwt}`,
          Accept: 'application/json',
        },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(15_000),
      });
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      throw new Sep24InitiationError(
        anchorDomain,
        `network error calling ${endpointUrl}: ${message}`,
      );
    }

    // ── Handle error responses ──────────────────────────────────────────────

    if (!response.ok) {
      let detail = '';

      try {
        const errBody = await response.json() as Record<string, unknown>;
        detail = (errBody['error'] ?? errBody['message'] ?? errBody['detail']) as string ?? '';
      } catch {
        detail = await response.text().catch(() => '');
      }

      const reason = `HTTP ${response.status}${detail ? `: ${detail}` : ''}`;

      if (response.status === 400) {
        throw new Sep24InitiationError(anchorDomain, `unsupported asset or bad request — ${reason}`, 400);
      }

      throw new Sep24InitiationError(anchorDomain, reason, response.status);
    }

    // ── Parse interactive response ──────────────────────────────────────────

    let data: Record<string, unknown>;

    try {
      data = await response.json() as Record<string, unknown>;
    } catch {
      throw new Sep24InitiationError(anchorDomain, 'anchor returned non-JSON response body');
    }

    if (data['type'] !== 'interactive_customer_info_needed') {
      throw new Sep24InitiationError(
        anchorDomain,
        `unexpected response type: ${String(data['type'])} (expected interactive_customer_info_needed)`,
      );
    }

    if (typeof data['url'] !== 'string' || !data['url']) {
      throw new Sep24InitiationError(anchorDomain, 'anchor response missing interactive URL');
    }

    const interactiveResponse: Sep24InteractiveResponse = {
      type: 'interactive_customer_info_needed',
      url: data['url'] as string,
    };

    if (typeof data['id'] === 'string') interactiveResponse.id = data['id'];
    if (typeof data['message'] === 'string') interactiveResponse.message = data['message'];

    this.logger.debug(
      `SEP-24 ${type} initiated for ${anchorDomain}: url=${interactiveResponse.url}`,
    );

    return interactiveResponse;
  }

  // ─── Transaction Polling (unchanged) ─────────────────────────────────────

  /**
   * Poll the anchor's SEP-24 /transaction endpoint for status of a single
   * transaction.
   *
   * URL format: https://{anchorDomain}/sep24/transaction?id={transactionId}
   * When a JWT is supplied it is passed as ?jwt={token}.
   *
   * @param opts - Poll options (anchorDomain, transactionId, optional jwt).
   * @returns AnchorPollResult — always resolves, never rejects.
   */
  async pollTransaction(opts: AnchorPollOptions): Promise<AnchorPollResult> {
    const { anchorDomain, transactionId, jwt } = opts;

    const params = new URLSearchParams({ id: transactionId });
    if (jwt) params.append('jwt', jwt);

    // Use HTTPS by default; strip any explicit scheme from the domain
    const cleanDomain = anchorDomain.replace(/^https?:\/\//, '');
    const url = `https://${cleanDomain}/sep24/transaction?${params.toString()}`;

    const startMs = Date.now();

    try {
      const response = await fetch(url, {
        method: 'GET',
        headers: {
          Accept: 'application/json',
        },
        // 10-second timeout to prevent a slow anchor from blocking the cycle
        signal: AbortSignal.timeout(10_000),
      });

      const duration = Date.now() - startMs;
      this.logger.debug(
        `Anchor poll ${anchorDomain} tx=${transactionId} → HTTP ${response.status} (${duration}ms)`,
      );

      if (!response.ok) {
        return {
          success: false,
          data: null,
          httpStatus: response.status,
          error: `Anchor returned HTTP ${response.status}`,
        };
      }

      const body = await response.json() as AnchorTransactionResponse;

      // Minimal structural validation
      if (!body?.transaction?.id || !body?.transaction?.status) {
        return {
          success: false,
          data: null,
          httpStatus: response.status,
          error: 'Anchor response missing required fields (transaction.id / transaction.status)',
        };
      }

      return { success: true, data: body, httpStatus: response.status, error: null };
    } catch (err) {
      const duration = Date.now() - startMs;
      const message = err instanceof Error ? err.message : String(err);

      this.logger.warn(
        `Anchor poll failed for ${anchorDomain} tx=${transactionId} after ${duration}ms: ${message}`,
      );

      return {
        success: false,
        data: null,
        httpStatus: null,
        error: message,
      };
    }
  }

  // ─── Legacy: resolveSep24TransferServer ──────────────────────────────────

  /**
   * Attempt to resolve the SEP-24 transfer server URL from the anchor's
   * stellar.toml file.
   *
   * Returns null on any failure so callers can fall back to a conventional URL.
   *
   * @deprecated Use {@link discoverAnchorCapabilities} instead for the full
   *             discovery flow.
   */
  async resolveSep24TransferServer(anchorDomain: string): Promise<string | null> {
    try {
      const caps = await this.discoverAnchorCapabilities(anchorDomain);
      return caps.transferServer;
    } catch {
      return null;
    }
  }
}
