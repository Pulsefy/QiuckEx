import {
  redactSensitiveValues,
  redactValue,
  sanitizeErrorMessage,
  createConfigSummary,
} from './redaction.util';

describe('Redaction Utilities', () => {
  describe('redactValue', () => {
    it('should redact short values completely', () => {
      expect(redactValue('short')).toBe('****');
    });

    it('should show first and last 4 characters for long values', () => {
      const value = 'abcd1234567890xyz1';
      const result = redactValue(value);
      expect(result).toBe('abcd********xyz1');
    });

    it('should limit mask length to 12 characters', () => {
      const veryLongValue = 'abcd' + 'x'.repeat(100) + 'xyz1';
      const result = redactValue(veryLongValue);
      expect(result).toBe('abcd************xyz1');
    });

    it('should handle empty string', () => {
      expect(redactValue('')).toBe('****');
    });
  });

  describe('redactSensitiveValues', () => {
    it('should redact sensitive environment variables', () => {
      const env = {
        SUPABASE_ANON_KEY: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test',
        STELLAR_SECRET_KEY: 'SABCDEFGHIJKLMNOPQRSTUVWXYZ234567',
        NETWORK: 'testnet',
        PORT: '4000',
      };

      const result = redactSensitiveValues(env);

      expect(result.SUPABASE_ANON_KEY).not.toContain('eyJhbGci');
      expect(result.SUPABASE_ANON_KEY).toContain('****');
      expect(result.STELLAR_SECRET_KEY).not.toContain('SABC');
      expect(result.NETWORK).toBe('testnet');
      expect(result.PORT).toBe('4000');
    });

    it('should not redact non-sensitive values', () => {
      const env = {
        NETWORK: 'mainnet',
        PORT: '3000',
        NODE_ENV: 'production',
      };

      const result = redactSensitiveValues(env);

      expect(result).toEqual(env);
    });

    it('should handle mixed sensitive and non-sensitive keys', () => {
      const env = {
        API_KEY: 'secret123',
        DATABASE_URL: 'postgres://localhost',
        TIMEOUT: '5000',
      };

      const result = redactSensitiveValues(env);

      expect(result.API_KEY).toBe('****');
      expect(result.DATABASE_URL).toBe('postgres://localhost');
      expect(result.TIMEOUT).toBe('5000');
    });
  });

  describe('sanitizeErrorMessage', () => {
    it('should redact Stellar secret keys', () => {
      const message = 'Error with key SABCDEFGHIJKLMNOPQRSTUVWXYZ234567abcdef';
      const result = sanitizeErrorMessage(message);
      expect(result).toContain('[REDACTED_SECRET_KEY]');
      expect(result).not.toContain('SABC');
    });

    it('should redact Stellar public keys', () => {
      const message = 'Invalid address GABCDEFGHIJKLMNOPQRSTUVWXYZ234567abcdef';
      const result = sanitizeErrorMessage(message);
      expect(result).toContain('[REDACTED_PUBLIC_KEY]');
      expect(result).not.toContain('GABC');
    });

    it('should redact JWT tokens', () => {
      const message =
        'Auth failed: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdef123456';
      const result = sanitizeErrorMessage(message);
      expect(result).toContain('[REDACTED_TOKEN]');
      expect(result).not.toContain('eyJhbG');
    });

    it('should redact Supabase JWT keys', () => {
      const message = 'Invalid token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test.signature';
      const result = sanitizeErrorMessage(message);
      expect(result).toContain('[REDACTED_JWT]');
    });

    it('should handle messages without sensitive data', () => {
      const message = 'Database connection failed';
      const result = sanitizeErrorMessage(message);
      expect(result).toBe(message);
    });
  });

  describe('createConfigSummary', () => {
    it('should show count of loaded configurations', () => {
      const config = {
        SUPABASE_URL: 'https://example.supabase.co',
        SUPABASE_ANON_KEY: 'key123',
        NETWORK: 'testnet',
        OPTIONAL_VAR: undefined,
      };

      const result = createConfigSummary(config);

      expect(result).toContain('3/3 required values loaded');
    });

    it('should list missing configurations', () => {
      const config = {
        SUPABASE_URL: 'https://example.supabase.co',
        NETWORK: undefined,
        PORT: '',
      };

      const result = createConfigSummary(config);

      expect(result).toContain('1/3 required values loaded');
      expect(result).toContain('Missing:');
    });

    it('should handle all configurations loaded', () => {
      const config = {
        VAR1: 'value1',
        VAR2: 'value2',
      };

      const result = createConfigSummary(config);

      expect(result).toContain('2/2 required values loaded');
      expect(result).not.toContain('Missing');
    });
  });
});
