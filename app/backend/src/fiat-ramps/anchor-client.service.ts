/**
 * Anchor Client Service
 *
 * Thin HTTP client for talking to SEP-24 anchor endpoints.
 * Handles the GET /sep24/transaction?id={id}&jwt={token} call pattern used
 * for polling transaction status.
 *
 * Retry / backoff is intentionally left to the caller (the polling service
 * tracks per-transaction failure counts so it can apply graduated backoff
 * without blocking the whole poll cycle).
 */

import { Injectable, Logger } from '@nestjs/common';
import { AnchorTransactionResponse } from './types/sep24.types';

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

@Injectable()
export class AnchorClientService {
  private readonly logger = new Logger(AnchorClientService.name);

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

  /**
   * Attempt to resolve the SEP-24 transfer server URL from the anchor's
   * stellar.toml file.
   *
   * Returns null on any failure so callers can fall back to a conventional URL.
   */
  async resolveSep24TransferServer(anchorDomain: string): Promise<string | null> {
    const cleanDomain = anchorDomain.replace(/^https?:\/\//, '');
    const tomlUrl = `https://${cleanDomain}/.well-known/stellar.toml`;

    try {
      const response = await fetch(tomlUrl, {
        method: 'GET',
        signal: AbortSignal.timeout(5_000),
      });

      if (!response.ok) return null;

      const text = await response.text();

      // Simple TOML field extraction for TRANSFER_SERVER_SEP0024
      const match = text.match(/TRANSFER_SERVER_SEP0024\s*=\s*["']([^"']+)["']/);
      return match ? match[1] : null;
    } catch {
      return null;
    }
  }
}
