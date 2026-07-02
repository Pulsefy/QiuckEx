import {
  maskStellarPublicKey,
  redactContext,
  redactFeedbackText,
} from '../utils/feedback-redaction';

// Valid-shaped Stellar keys (56 chars, base32 alphabet A-Z2-7).
const PUBLIC_KEY = 'GABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOPQRSTUVWX';
const SECRET_KEY = 'SABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOPQRSTUVWX';

describe('feedback redaction', () => {
  describe('redactFeedbackText', () => {
    it('fully removes Stellar secret seeds', () => {
      const result = redactFeedbackText(`my seed is ${SECRET_KEY} keep it safe`);
      expect(result).toBe('my seed is [REDACTED_SECRET_KEY] keep it safe');
      expect(result).not.toContain(SECRET_KEY);
    });

    it('masks Stellar public keys', () => {
      const result = redactFeedbackText(`paid ${PUBLIC_KEY} today`);
      expect(result).toBe(`paid ${maskStellarPublicKey(PUBLIC_KEY)} today`);
      expect(result).not.toContain(PUBLIC_KEY);
    });

    it('still redacts standard PII (email)', () => {
      expect(redactFeedbackText('reach me at a@b.com')).toBe('reach me at [EMAIL]');
    });

    it('handles multiple sensitive values in one string', () => {
      const input = `from ${PUBLIC_KEY} using ${SECRET_KEY} email x@y.com`;
      const result = redactFeedbackText(input);
      expect(result).toContain(maskStellarPublicKey(PUBLIC_KEY));
      expect(result).toContain('[REDACTED_SECRET_KEY]');
      expect(result).toContain('[EMAIL]');
      expect(result).not.toContain(SECRET_KEY);
    });

    it('passes through empty input unchanged', () => {
      expect(redactFeedbackText('')).toBe('');
    });
  });

  describe('maskStellarPublicKey', () => {
    it('keeps a prefix and suffix', () => {
      expect(maskStellarPublicKey(PUBLIC_KEY)).toBe('GABC…UVWX');
    });

    it('leaves short strings untouched', () => {
      expect(maskStellarPublicKey('GABC')).toBe('GABC');
    });
  });

  describe('redactContext', () => {
    it('recursively scrubs string values in nested objects', () => {
      const result = redactContext({
        note: `seed ${SECRET_KEY}`,
        nested: { addresses: [PUBLIC_KEY, 'plain text'] },
        count: 3,
      });

      expect(result.note).toBe('seed [REDACTED_SECRET_KEY]');
      expect(result.nested.addresses[0]).toBe(maskStellarPublicKey(PUBLIC_KEY));
      expect(result.nested.addresses[1]).toBe('plain text');
      // Non-string values are preserved as-is.
      expect(result.count).toBe(3);
    });
  });
});
