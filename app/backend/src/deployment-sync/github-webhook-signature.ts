import { createHmac, timingSafeEqual } from 'crypto';

/**
 * GitHub webhook signature verification (BE-60).
 *
 * GitHub signs the raw request body with HMAC-SHA256 using the shared webhook
 * secret and sends it in the `X-Hub-Signature-256` header as
 * `sha256=<hex digest>`. Verification MUST run against the exact raw bytes of
 * the body — re-serializing the parsed JSON would break the digest.
 */
export function verifyGithubSignature(
  rawBody: Buffer | undefined,
  signature: string | undefined,
  secret: string | undefined,
): boolean {
  if (!rawBody || rawBody.length === 0 || !signature || !secret) {
    return false;
  }

  const expected = signature.startsWith('sha256=') ? signature.slice(7) : signature;

  const actual = createHmac('sha256', secret).update(rawBody).digest('hex');

  try {
    return timingSafeEqual(Buffer.from(expected, 'hex'), Buffer.from(actual, 'hex'));
  } catch {
    // Malformed expected digest (e.g. wrong length) makes timingSafeEqual throw.
    return false;
  }
}
