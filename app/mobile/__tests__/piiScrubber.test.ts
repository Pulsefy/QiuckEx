import { scrubPii } from '../utils/piiScrubber';
import { PII_FIXTURES } from './fixtures/piiFixtures';

describe('PII Scrubber Regression Tests', () => {
  describe('Expected Transformations', () => {
    it('should correctly redact email addresses', () => {
      PII_FIXTURES.emails.forEach(({ input, expected }) => {
        expect(scrubPii(input)).toBe(expected);
      });
    });

    it('should correctly redact phone numbers', () => {
      PII_FIXTURES.phones.forEach(({ input, expected }) => {
        expect(scrubPii(input)).toBe(expected);
      });
    });

    it('should correctly redact sensitive IDs (SSN, Cards)', () => {
      PII_FIXTURES.ids.forEach(({ input, expected }) => {
        expect(scrubPii(input)).toBe(expected);
      });
    });
  });

  describe('False Positive Guard', () => {
    it('should not mutate safe text and non-PII numerical data', () => {
      PII_FIXTURES.safeText.forEach(({ input, expected }) => {
        expect(scrubPii(input)).toBe(expected);
      });
    });
  });

  describe('Edge Cases', () => {
    it('should handle empty or null strings gracefully', () => {
      expect(scrubPii('')).toBe('');
      // @ts-ignore testing invalid input for robustness
      expect(scrubPii(null)).toBe(null);
    });

    it('should handle multiple PII types in a single string', () => {
      const input = "User test@test.com called (555) 987-6543 about card 4532 1234 5678 9012.";
      const expected = "User [EMAIL] called [PHONE] about card [CARD].";
      expect(scrubPii(input)).toBe(expected);
    });
  });
});
