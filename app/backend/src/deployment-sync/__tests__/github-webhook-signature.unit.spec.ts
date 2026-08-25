import { createHmac } from 'crypto';

import { verifyGithubSignature } from '../github-webhook-signature';

describe('verifyGithubSignature (BE-60)', () => {
  const secret = 'test-secret';
  const body = Buffer.from('{"branch":"main","ok":true}');

  function sign(): string {
    return `sha256=${createHmac('sha256', secret).update(body).digest('hex')}`;
  }

  it('verifies a valid sha256 HMAC signature', () => {
    expect(verifyGithubSignature(body, sign(), secret)).toBe(true);
  });

  it('accepts a signature without the sha256= prefix', () => {
    const bare = sign().replace('sha256=', '');
    expect(verifyGithubSignature(body, bare, secret)).toBe(true);
  });

  it('rejects a signature produced with a different secret', () => {
    const other = `sha256=${createHmac('sha256', 'wrong-secret').update(body).digest('hex')}`;
    expect(verifyGithubSignature(body, other, secret)).toBe(false);
  });

  it('rejects a malformed signature', () => {
    expect(verifyGithubSignature(body, 'sha256=not-hex', secret)).toBe(false);
    expect(verifyGithubSignature(body, 'sha256=abcd', secret)).toBe(false);
  });

  it('rejects when raw body, signature, or secret is missing', () => {
    expect(verifyGithubSignature(undefined, sign(), secret)).toBe(false);
    expect(verifyGithubSignature(body, undefined, secret)).toBe(false);
    expect(verifyGithubSignature(body, sign(), undefined)).toBe(false);
    expect(verifyGithubSignature(Buffer.alloc(0), sign(), secret)).toBe(false);
  });
});
