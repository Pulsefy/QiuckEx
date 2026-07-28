import { Injectable } from '@nestjs/common';

/**
 * Service responsible for redacting sensitive information from logs and crash reports.
 * Ensures no secrets, keys, or PII are included in captured data.
 */
@Injectable()
export class RedactionService {
  // Patterns for sensitive data that should be redacted
  private readonly sensitivePatterns = [
    // Stellar keys
    { pattern: /G[A-Z0-9]{55}/gi, replacement: '[REDACTED_PUBLIC_KEY]' },
    { pattern: /S[A-Z0-9]{55}/gi, replacement: '[REDACTED_SECRET_KEY]' },
    
    // Bearer tokens (must come before JWT pattern to handle "Bearer eyJ..." as a token)
    { pattern: /Bearer\s+[A-Za-z0-9\-._~+/]+=*/gi, replacement: 'Bearer [REDACTED_TOKEN]' },
    
    // JWT tokens
    { pattern: /eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+/gi, replacement: '[REDACTED_JWT]' },
    
    // API keys and tokens (more specific patterns first)
    { pattern: /api[_-]?\s*key\s*[:=]\s*[A-Za-z0-9\-._~+/]+/gi, replacement: 'api_key=[REDACTED_API_KEY]' },
    { pattern: /\b[A-Za-z][A-Za-z0-9]*_key_[A-Za-z0-9._~+/=-]+\b/gi, replacement: '[REDACTED_API_KEY]' },
    { pattern: /token["\s:=]+(?!eyJ)[A-Za-z0-9\-._~+/]+/gi, replacement: 'token=[REDACTED_TOKEN]' },
    { pattern: /secret["\s:=]+[A-Za-z0-9\-._~+/]+/gi, replacement: 'secret=[REDACTED_SECRET]' },
    { pattern: /password["\s:=]+[^\s"',}]+/gi, replacement: 'password=[REDACTED_PASSWORD]' },
    
    // Email addresses (PII)
    { pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/gi, replacement: '[REDACTED_EMAIL]' },
    
    // IP addresses (PII)
    { pattern: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g, replacement: '[REDACTED_IP]' },
    { pattern: /\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b/g, replacement: '[REDACTED_IPV6]' },
    
    // Credit card numbers (PII)
    { pattern: /\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/g, replacement: '[REDACTED_CARD]' },
    
    // Phone numbers (PII)
    { pattern: /\b\+?[\d\s()-]{10,}\b/g, replacement: '[REDACTED_PHONE]' },
    
    // Authorization headers
    { pattern: /authorization["\s:=]+(?!Bearer)[^\s"',}]+/gi, replacement: 'authorization=[REDACTED_AUTH]' },
    
    // Database connection strings
    { pattern: /postgres:\/\/[^\s"']+/gi, replacement: 'postgres://[REDACTED_DB_CONNECTION]' },
    { pattern: /mongodb:\/\/[^\s"']+/gi, replacement: 'mongodb://[REDACTED_DB_CONNECTION]' },
    
    // Environment variable values in logs
    { pattern: /(SUPABASE_SERVICE_ROLE_KEY|STELLAR_SECRET_KEY|SENDGRID_API_KEY|EXPO_ACCESS_TOKEN|API_KEYS)["\s:=]+[^\s"',}]+/gi, replacement: '$1=[REDACTED]' },
  ];

  /**
   * Redact sensitive information from a string
   * @param text - The text to redact
   * @returns The redacted text
   */
  redact(text: string): string {
    if (!text) {
      return text;
    }

    let redacted = text;
    
    for (const { pattern, replacement } of this.sensitivePatterns) {
      redacted = redacted.replace(pattern, replacement);
    }

    return redacted;
  }

  /**
   * Redact sensitive information from an object
   * @param obj - The object to redact
   * @returns A new object with redacted values
   */
  redactObject(obj: unknown): unknown {
    if (obj === null || obj === undefined) {
      return obj;
    }

    if (typeof obj === 'string') {
      return this.redact(obj);
    }

    if (typeof obj === 'number' || typeof obj === 'boolean') {
      return obj;
    }

    if (Array.isArray(obj)) {
      return obj.map(item => this.redactObject(item));
    }

    if (typeof obj === 'object') {
      const redacted: Record<string, unknown> = {};
      
      for (const [key, value] of Object.entries(obj)) {
        // Redact known sensitive keys entirely
        const lowerKey = key.toLowerCase();
        if (
          lowerKey.includes('password') ||
          lowerKey.includes('secret') ||
          lowerKey.includes('token') ||
          lowerKey.includes('key') && (lowerKey.includes('api') || lowerKey.includes('private') || lowerKey.includes('public')) ||
          lowerKey.includes('authorization') ||
          lowerKey.includes('auth')
        ) {
          redacted[key] = '[REDACTED]';
        } else {
          redacted[key] = this.redactObject(value);
        }
      }
      
      return redacted;
    }

    return obj;
  }

  /**
   * Redact sensitive information from an error object
   * @param error - The error to redact
   * @returns A redacted error representation
   */
  redactError(error: Error): { name: string; message: string; stack?: string } {
    return {
      name: error.name,
      message: this.redact(error.message),
      stack: error.stack ? this.redact(error.stack) : undefined,
    };
  }

  /**
   * Redact sensitive information from log lines
   * @param logLines - Array of log lines
   * @returns Array of redacted log lines
   */
  redactLogLines(logLines: string[]): string[] {
    return logLines.map(line => this.redact(line));
  }
}
