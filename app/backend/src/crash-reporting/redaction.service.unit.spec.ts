import { Test, TestingModule } from '@nestjs/testing';
import { RedactionService } from './redaction.service';

describe('RedactionService', () => {
  let service: RedactionService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [RedactionService],
    }).compile();

    service = module.get<RedactionService>(RedactionService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('redact', () => {
    it('should redact Stellar public keys', () => {
      const text = 'Public key: GBRPYHIL2CI3FNQ4BXLFMNDLFJUNPU2HY3ZMFSHONUCEOASW7QC7OX2H';
      const result = service.redact(text);
      expect(result).toBe('Public key: [REDACTED_PUBLIC_KEY]');
      expect(result).not.toContain('GBRPYHIL2CI3FNQ4BXLFMNDLFJUNPU2HY3ZMFSHONUCEOASW7QC7OX2H');
    });

    it('should redact Stellar secret keys', () => {
      const text = 'Secret: SBZVMB74Z76QZ3ZOY3XRXEPNQN754WKRGMAG4OQIPOOB6QMHIDCNVYKY';
      const result = service.redact(text);
      expect(result).toBe('Secret: [REDACTED_SECRET_KEY]');
      expect(result).not.toContain('SBZVMB74Z76QZ3ZOY3XRXEPNQN754WKRGMAG4OQIPOOB6QMHIDCNVYKY');
    });

    it('should redact Bearer tokens', () => {
      const text = 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U';
      const result = service.redact(text);
      expect(result).toBe('Authorization: Bearer [REDACTED_TOKEN]');
      expect(result).not.toContain('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9');
    });

    it('should redact API keys', () => {
      const text = 'api_key=test_key_1234567890abcdef';
      const result = service.redact(text);
      expect(result).toBe('api_key=[REDACTED_API_KEY]');
      expect(result).not.toContain('test_key_1234567890abcdef');
    });

    it('should redact passwords', () => {
      const text = 'password=mySecretPassword123';
      const result = service.redact(text);
      expect(result).toBe('password=[REDACTED_PASSWORD]');
      expect(result).not.toContain('mySecretPassword123');
    });

    it('should redact JWT tokens', () => {
      const text = 'Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
      const result = service.redact(text);
      expect(result).toBe('Token: [REDACTED_JWT]');
      expect(result).not.toContain('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9');
    });

    it('should redact email addresses', () => {
      const text = 'User email: user@example.com';
      const result = service.redact(text);
      expect(result).toBe('User email: [REDACTED_EMAIL]');
      expect(result).not.toContain('user@example.com');
    });

    it('should redact IPv4 addresses', () => {
      const text = 'IP address: 192.168.1.1';
      const result = service.redact(text);
      expect(result).toBe('IP address: [REDACTED_IP]');
      expect(result).not.toContain('192.168.1.1');
    });

    it('should redact IPv6 addresses', () => {
      const text = 'IPv6: 2001:0db8:85a3:0000:0000:8a2e:0370:7334';
      const result = service.redact(text);
      expect(result).toBe('IPv6: [REDACTED_IPV6]');
      expect(result).not.toContain('2001:0db8:85a3:0000:0000:8a2e:0370:7334');
    });

    it('should redact credit card numbers', () => {
      const text = 'Card: 4532-1234-5678-9010';
      const result = service.redact(text);
      expect(result).toBe('Card: [REDACTED_CARD]');
      expect(result).not.toContain('4532-1234-5678-9010');
    });

    it('should redact database connection strings', () => {
      const text = 'DB: postgres://user:password@localhost:5432/mydb';
      const result = service.redact(text);
      expect(result).toBe('DB: postgres://[REDACTED_DB_CONNECTION]');
      expect(result).not.toContain('user:password@localhost:5432/mydb');
    });

    it('should redact environment variable values', () => {
      const text = 'STELLAR_SECRET_KEY=SBZVMB74Z76QZ3ZOY3XRXEPNQN754WKRGMAG4OQIPOOB6QMHIDCNVYKY';
      const result = service.redact(text);
      expect(result).toBe('STELLAR_SECRET_KEY=[REDACTED]');
      expect(result).not.toContain('SBZVMB74Z76QZ3ZOY3XRXEPNQN754WKRGMAG4OQIPOOB6QMHIDCNVYKY');
    });

    it('should handle multiple sensitive values in one string', () => {
      const text = 'User user@example.com with key GBRPYHIL2CI3FNQ4BXLFMNDLFJUNPU2HY3ZMFSHONUCEOASW7QC7OX2H from IP 192.168.1.1';
      const result = service.redact(text);
      expect(result).not.toContain('user@example.com');
      expect(result).not.toContain('GBRPYHIL2CI3FNQ4BXLFMNDLFJUNPU2HY3ZMFSHONUCEOASW7QC7OX2H');
      expect(result).not.toContain('192.168.1.1');
      expect(result).toContain('[REDACTED_EMAIL]');
      expect(result).toContain('[REDACTED_PUBLIC_KEY]');
      expect(result).toContain('[REDACTED_IP]');
    });

    it('should return empty string for empty input', () => {
      expect(service.redact('')).toBe('');
    });

    it('should handle null and undefined', () => {
      expect(service.redact(null as unknown as string)).toBeNull();
      expect(service.redact(undefined as unknown as string)).toBeUndefined();
    });
  });

  describe('redactObject', () => {
    it('should redact string values in objects', () => {
      const obj = {
        publicKey: 'GBRPYHIL2CI3FNQ4BXLFMNDLFJUNPU2HY3ZMFSHONUCEOASW7QC7OX2H',
        email: 'user@example.com',
      };
      const result = service.redactObject(obj) as Record<string, unknown>;
      expect(result.publicKey).toBe('[REDACTED]');
      expect(result.email).toBe('[REDACTED_EMAIL]');
    });

    it('should redact sensitive keys entirely', () => {
      const obj = {
        password: 'myPassword123',
        apiKey: 'test_key_1234567890',
        secretToken: 'secret123',
        normalField: 'safe value',
      };
      const result = service.redactObject(obj) as Record<string, unknown>;
      expect(result.password).toBe('[REDACTED]');
      expect(result.apiKey).toBe('[REDACTED]');
      expect(result.secretToken).toBe('[REDACTED]');
      expect(result.normalField).toBe('safe value');
    });

    it('should handle nested objects', () => {
      const obj = {
        user: {
          email: 'user@example.com',
          credentials: {
            password: 'secret123',
          },
        },
      };
      const result = service.redactObject(obj) as Record<string, Record<string, unknown>>;
      expect((result.user as Record<string, unknown>).email).toBe('[REDACTED_EMAIL]');
      expect(((result.user as Record<string, unknown>).credentials as Record<string, unknown>).password).toBe('[REDACTED]');
    });

    it('should handle arrays', () => {
      const obj = {
        emails: ['user1@example.com', 'user2@example.com'],
      };
      const result = service.redactObject(obj) as Record<string, string[]>;
      expect(result.emails[0]).toBe('[REDACTED_EMAIL]');
      expect(result.emails[1]).toBe('[REDACTED_EMAIL]');
    });

    it('should preserve numbers and booleans', () => {
      const obj = {
        count: 42,
        enabled: true,
        ratio: 3.14,
      };
      const result = service.redactObject(obj) as Record<string, number | boolean>;
      expect(result.count).toBe(42);
      expect(result.enabled).toBe(true);
      expect(result.ratio).toBe(3.14);
    });

    it('should handle null and undefined values', () => {
      const obj = {
        nullValue: null,
        undefinedValue: undefined,
      };
      const result = service.redactObject(obj) as Record<string, null | undefined>;
      expect(result.nullValue).toBeNull();
      expect(result.undefinedValue).toBeUndefined();
    });
  });

  describe('redactError', () => {
    it('should redact error messages', () => {
      const error = new Error('Failed to connect to GBRPYHIL2CI3FNQ4BXLFMNDLFJUNPU2HY3ZMFSHONUCEOASW7QC7OX2H');
      const result = service.redactError(error);
      expect(result.message).not.toContain('GBRPYHIL2CI3FNQ4BXLFMNDLFJUNPU2HY3ZMFSHONUCEOASW7QC7OX2H');
      expect(result.message).toContain('[REDACTED_PUBLIC_KEY]');
    });

    it('should redact error stack traces', () => {
      const error = new Error('Database error');
      error.stack = 'Error: Database error\n  at postgres://user:pass@localhost:5432/db';
      const result = service.redactError(error);
      expect(result.stack).not.toContain('user:pass@localhost:5432/db');
      expect(result.stack).toContain('[REDACTED_DB_CONNECTION]');
    });

    it('should preserve error name', () => {
      const error = new TypeError('Invalid type');
      const result = service.redactError(error);
      expect(result.name).toBe('TypeError');
    });
  });

  describe('redactLogLines', () => {
    it('should redact multiple log lines', () => {
      const logs = [
        'INFO: User logged in with email user@example.com',
        'DEBUG: API key: test_key_1234567890',
        'ERROR: Failed to connect to 192.168.1.1',
      ];
      const result = service.redactLogLines(logs);
      expect(result[0]).not.toContain('user@example.com');
      expect(result[1]).not.toContain('test_key_1234567890');
      expect(result[2]).not.toContain('192.168.1.1');
      expect(result[0]).toContain('[REDACTED_EMAIL]');
      expect(result[1]).toContain('[REDACTED_API_KEY]');
      expect(result[2]).toContain('[REDACTED_IP]');
    });

    it('should handle empty array', () => {
      const result = service.redactLogLines([]);
      expect(result).toEqual([]);
    });
  });

  describe('comprehensive redaction validation', () => {
    it('should never leak Stellar secret keys in any format', () => {
      const secretKey = 'SBZVMB74Z76QZ3ZOY3XRXEPNQN754WKRGMAG4OQIPOOB6QMHIDCNVYKY';
      const testCases = [
        `Secret: ${secretKey}`,
        `"secret_key": "${secretKey}"`,
        `STELLAR_SECRET_KEY=${secretKey}`,
        `Authorization: ${secretKey}`,
        JSON.stringify({ key: secretKey }),
      ];

      testCases.forEach(testCase => {
        const result = service.redact(testCase);
        expect(result).not.toContain(secretKey);
      });
    });

    it('should never leak API keys in any format', () => {
      const apiKey = 'test_key_1234567890abcdefghijklmnop';
      const testCases = [
        `api_key=${apiKey}`,
        `"apiKey": "${apiKey}"`,
        `API_KEY=${apiKey}`,
        `Bearer ${apiKey}`,
      ];

      testCases.forEach(testCase => {
        const result = service.redact(testCase);
        expect(result).not.toContain(apiKey);
      });
    });

    it('should never leak PII (emails, IPs) in any format', () => {
      const email = 'sensitive@example.com';
      const ip = '203.0.113.42';
      const testCases = [
        `User: ${email}`,
        `From IP: ${ip}`,
        `{"email": "${email}", "ip": "${ip}"}`,
      ];

      testCases.forEach(testCase => {
        const result = service.redact(testCase);
        expect(result).not.toContain(email);
        expect(result).not.toContain(ip);
      });
    });
  });
});
