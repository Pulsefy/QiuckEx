import { scrubPii } from './piiScrubber';

/**
 * Privacy-safe redaction for feedback context.
 *
 * Feedback submissions can carry attached context (free-text descriptions,
 * exported logs, copied error payloads) that may contain sensitive values.
 * QuickEx is a Stellar wallet, so the highest-risk leak is a secret seed or a
 * raw account public key — neither of which the generic {@link scrubPii}
 * handles. This module layers Stellar-aware redaction on top of the existing
 * PII scrubber so a single call covers emails/phones/cards *and* wallet keys.
 */

// Stellar secret seeds start with `S` and are 56 base32 chars. These must never
// leave the device — redact aggressively.
const STELLAR_SECRET = /\bS[A-Z2-7]{55}\b/g;

// Stellar public keys start with `G` and are 56 base32 chars. Not secret, but
// they identify a user's account, so we partially mask rather than drop them —
// keeping a prefix/suffix lets contributors correlate reports without exposing
// the full address.
const STELLAR_PUBLIC_KEY = /\bG[A-Z2-7]{55}\b/g;

/**
 * Mask a Stellar public key to `GABC…WXYZ`, preserving enough to correlate
 * reports while removing the full identifier.
 */
export function maskStellarPublicKey(key: string): string {
  if (key.length < 12) return key;
  return `${key.slice(0, 4)}…${key.slice(-4)}`;
}

/**
 * Redact sensitive values from a single string: standard PII plus Stellar
 * secret seeds (fully removed) and public keys (masked).
 */
export function redactFeedbackText(text: string): string {
  if (!text) return text;

  let redacted = text.replace(STELLAR_SECRET, '[REDACTED_SECRET_KEY]');
  redacted = redacted.replace(STELLAR_PUBLIC_KEY, (match) =>
    maskStellarPublicKey(match),
  );

  // Run the shared PII scrubber last so its replacement tokens (e.g. [EMAIL])
  // are never themselves matched by the Stellar patterns above.
  return scrubPii(redacted);
}

/**
 * Recursively redact every string value in a context object. Keys are left
 * intact; only values are scrubbed. Useful for sanitising structured metadata
 * before it is attached to a feedback payload.
 */
export function redactContext<T>(value: T): T {
  if (typeof value === 'string') {
    return redactFeedbackText(value) as unknown as T;
  }
  if (Array.isArray(value)) {
    return value.map((item) => redactContext(item)) as unknown as T;
  }
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [key, val] of Object.entries(value)) {
      out[key] = redactContext(val);
    }
    return out as T;
  }
  return value;
}
