/**
 * Unit tests for webhook-target.util.ts SSRF protection.
 *
 * Covers:
 *  - isBlockedIp() — loopback, private RFC1918, link-local, cloud-metadata,
 *                    CGNAT, unspecified, IPv6 equivalents, IPv4-mapped IPv6
 *  - isDeliverableWebhookUrl() — protocol / format check
 *  - isWebhookUrlSafe() — synchronous fast-path check
 *  - validateWebhookTarget() — async DNS + IP-range check
 */

import {
  isBlockedIp,
  isDeliverableWebhookUrl,
  isWebhookUrlSafe,
  validateWebhookTarget,
  WebhookTargetBlockedError,
  InvalidWebhookUrlError,
} from '../webhook-target.util';
import { lookup as dnsLookupReal } from 'dns/promises';

// ---------------------------------------------------------------------------
// Mock dns/promises so we never make real network calls in unit tests.
// ---------------------------------------------------------------------------
jest.mock('dns/promises', () => ({
  lookup: jest.fn(),
}));

// Typed handle to the mocked lookup function for per-test configuration.
// The double cast is needed because the import type is the real function
// signature (with complex overloads), but at runtime jest.mock replaces it
// with a jest.Mock that accepts any mock return value.
const dnsLookup = dnsLookupReal as unknown as jest.Mock;

// Helper to configure the mock to return a single resolved address.
function mockDnsResolve(address: string): void {
  dnsLookup.mockResolvedValue([{ address, family: 4 }]);
}

// Helper to configure the mock to return multiple addresses.
function mockDnsResolveMany(addresses: string[]): void {
  dnsLookup.mockResolvedValue(
    addresses.map((address) => ({ address, family: 4 })),
  );
}

// Helper to configure the mock to reject (simulate DNS failure).
function mockDnsFail(message = 'ENOTFOUND example.internal'): void {
  dnsLookup.mockRejectedValue(new Error(message));
}

// ---------------------------------------------------------------------------
// isBlockedIp
// ---------------------------------------------------------------------------
describe('isBlockedIp', () => {
  describe('loopback addresses', () => {
    it('blocks 127.0.0.1', () => {
      expect(isBlockedIp('127.0.0.1')).toBe(true);
    });

    it('blocks 127.255.255.255 (end of loopback range)', () => {
      expect(isBlockedIp('127.255.255.255')).toBe(true);
    });

    it('blocks ::1 (IPv6 loopback)', () => {
      expect(isBlockedIp('::1')).toBe(true);
    });
  });

  describe('private RFC1918 ranges', () => {
    it('blocks 10.0.0.1 (10.0.0.0/8)', () => {
      expect(isBlockedIp('10.0.0.1')).toBe(true);
    });

    it('blocks 10.255.255.255 (end of 10/8)', () => {
      expect(isBlockedIp('10.255.255.255')).toBe(true);
    });

    it('blocks 172.16.0.1 (172.16.0.0/12)', () => {
      expect(isBlockedIp('172.16.0.1')).toBe(true);
    });

    it('blocks 172.31.255.255 (end of 172.16/12)', () => {
      expect(isBlockedIp('172.31.255.255')).toBe(true);
    });

    it('allows 172.15.255.255 (just below 172.16/12)', () => {
      expect(isBlockedIp('172.15.255.255')).toBe(false);
    });

    it('allows 172.32.0.0 (just above 172.16/12)', () => {
      expect(isBlockedIp('172.32.0.0')).toBe(false);
    });

    it('blocks 192.168.0.1 (192.168.0.0/16)', () => {
      expect(isBlockedIp('192.168.0.1')).toBe(true);
    });

    it('blocks 192.168.255.255 (end of 192.168/16)', () => {
      expect(isBlockedIp('192.168.255.255')).toBe(true);
    });
  });

  describe('link-local and cloud-metadata addresses', () => {
    it('blocks 169.254.169.254 (AWS/GCP/Azure metadata)', () => {
      expect(isBlockedIp('169.254.169.254')).toBe(true);
    });

    it('blocks 169.254.0.1 (start of link-local)', () => {
      expect(isBlockedIp('169.254.0.1')).toBe(true);
    });

    it('blocks 169.254.255.255 (end of link-local)', () => {
      expect(isBlockedIp('169.254.255.255')).toBe(true);
    });

    it('blocks fe80::1 (IPv6 link-local)', () => {
      expect(isBlockedIp('fe80::1')).toBe(true);
    });
  });

  describe('CGNAT range', () => {
    it('blocks 100.64.0.1 (start of CGNAT)', () => {
      expect(isBlockedIp('100.64.0.1')).toBe(true);
    });

    it('blocks 100.127.255.255 (end of CGNAT)', () => {
      expect(isBlockedIp('100.127.255.255')).toBe(true);
    });

    it('allows 100.63.255.255 (just below CGNAT)', () => {
      expect(isBlockedIp('100.63.255.255')).toBe(false);
    });

    it('allows 100.128.0.0 (just above CGNAT)', () => {
      expect(isBlockedIp('100.128.0.0')).toBe(false);
    });
  });

  describe('unspecified addresses', () => {
    it('blocks 0.0.0.0', () => {
      expect(isBlockedIp('0.0.0.0')).toBe(true);
    });

    it('blocks :: (IPv6 unspecified)', () => {
      expect(isBlockedIp('::')).toBe(true);
    });
  });

  describe('IPv6 unique-local (fc00::/7)', () => {
    it('blocks fc00::1', () => {
      expect(isBlockedIp('fc00::1')).toBe(true);
    });

    it('blocks fd00::1', () => {
      expect(isBlockedIp('fd00::1')).toBe(true);
    });
  });

  describe('IPv4-mapped IPv6 addresses', () => {
    it('blocks ::ffff:127.0.0.1 (loopback via IPv4-mapped)', () => {
      expect(isBlockedIp('::ffff:127.0.0.1')).toBe(true);
    });

    it('blocks ::ffff:169.254.169.254 (metadata via IPv4-mapped)', () => {
      expect(isBlockedIp('::ffff:169.254.169.254')).toBe(true);
    });

    it('blocks ::ffff:10.0.0.1 (private via IPv4-mapped)', () => {
      expect(isBlockedIp('::ffff:10.0.0.1')).toBe(true);
    });

    it('blocks ::ffff:192.168.1.1 (private via IPv4-mapped)', () => {
      expect(isBlockedIp('::ffff:192.168.1.1')).toBe(true);
    });
  });

  describe('public / safe addresses', () => {
    it('allows 1.1.1.1 (Cloudflare DNS)', () => {
      expect(isBlockedIp('1.1.1.1')).toBe(false);
    });

    it('allows 8.8.8.8 (Google DNS)', () => {
      expect(isBlockedIp('8.8.8.8')).toBe(false);
    });

    it('allows 104.18.23.1 (Cloudflare CDN)', () => {
      expect(isBlockedIp('104.18.23.1')).toBe(false);
    });

    it('allows 2606:4700::6810:8 (public IPv6)', () => {
      expect(isBlockedIp('2606:4700::6810:8')).toBe(false);
    });
  });

  describe('invalid inputs', () => {
    it('treats unparseable strings as blocked (fail-closed)', () => {
      expect(isBlockedIp('not-an-ip')).toBe(true);
    });

    it('treats empty string as blocked', () => {
      expect(isBlockedIp('')).toBe(true);
    });
  });
});

// ---------------------------------------------------------------------------
// isDeliverableWebhookUrl
// ---------------------------------------------------------------------------
describe('isDeliverableWebhookUrl', () => {
  it('accepts a valid https URL', () => {
    expect(isDeliverableWebhookUrl('https://example.com/hook')).toBe(true);
  });

  it('rejects http URLs', () => {
    expect(isDeliverableWebhookUrl('http://example.com/hook')).toBe(false);
  });

  it('rejects null', () => {
    expect(isDeliverableWebhookUrl(null)).toBe(false);
  });

  it('rejects undefined', () => {
    expect(isDeliverableWebhookUrl(undefined)).toBe(false);
  });

  it('rejects empty string', () => {
    expect(isDeliverableWebhookUrl('')).toBe(false);
  });

  it('rejects a relative path', () => {
    expect(isDeliverableWebhookUrl('/hooks/receive')).toBe(false);
  });

  it('rejects malformed URLs', () => {
    expect(isDeliverableWebhookUrl('not a url')).toBe(false);
  });

  it('accepts https with custom port', () => {
    expect(isDeliverableWebhookUrl('https://example.com:8443/hook')).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// isWebhookUrlSafe
// ---------------------------------------------------------------------------
describe('isWebhookUrlSafe', () => {
  it('returns true for a valid https URL with a hostname', () => {
    expect(isWebhookUrlSafe('https://example.com/hook')).toBe(true);
  });

  it('returns false for http', () => {
    expect(isWebhookUrlSafe('http://example.com/hook')).toBe(false);
  });

  it('returns false for null', () => {
    expect(isWebhookUrlSafe(null)).toBe(false);
  });

  it('returns false for an https URL with a blocked raw IP (127.0.0.1)', () => {
    expect(isWebhookUrlSafe('https://127.0.0.1/hook')).toBe(false);
  });

  it('returns false for an https URL with the metadata IP', () => {
    expect(isWebhookUrlSafe('https://169.254.169.254/latest/meta-data/')).toBe(
      false,
    );
  });

  it('returns true for an https URL with a public raw IP', () => {
    expect(isWebhookUrlSafe('https://1.1.1.1/hook')).toBe(true);
  });

  it('returns false for a malformed URL', () => {
    expect(isWebhookUrlSafe('://garbage')).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// validateWebhookTarget (async, uses mocked DNS)
// ---------------------------------------------------------------------------
describe('validateWebhookTarget', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  // ---- Format / protocol errors -------------------------------------------

  it('throws InvalidWebhookUrlError for http scheme', async () => {
    await expect(
      validateWebhookTarget('http://example.com/hook'),
    ).rejects.toBeInstanceOf(InvalidWebhookUrlError);
  });

  it('throws InvalidWebhookUrlError for a malformed URL', async () => {
    await expect(
      validateWebhookTarget('not-a-url'),
    ).rejects.toBeInstanceOf(InvalidWebhookUrlError);
  });

  it('throws InvalidWebhookUrlError for empty string', async () => {
    await expect(
      validateWebhookTarget(''),
    ).rejects.toBeInstanceOf(InvalidWebhookUrlError);
  });

  // ---- Raw IP in URL (no DNS needed) ---------------------------------------

  it('throws WebhookTargetBlockedError for https://127.0.0.1/', async () => {
    const err = await validateWebhookTarget('https://127.0.0.1/hook').catch(
      (e) => e,
    );
    expect(err).toBeInstanceOf(WebhookTargetBlockedError);
    expect((err as WebhookTargetBlockedError).hostname).toBe('127.0.0.1');
    expect((err as WebhookTargetBlockedError).resolvedIp).toBe('127.0.0.1');
  });

  it('throws WebhookTargetBlockedError for https://169.254.169.254/', async () => {
    await expect(
      validateWebhookTarget('https://169.254.169.254/latest/meta-data/'),
    ).rejects.toBeInstanceOf(WebhookTargetBlockedError);
  });

  it('throws WebhookTargetBlockedError for https://192.168.1.1/', async () => {
    await expect(
      validateWebhookTarget('https://192.168.1.1/'),
    ).rejects.toBeInstanceOf(WebhookTargetBlockedError);
  });

  it('throws WebhookTargetBlockedError for https://10.0.0.1/', async () => {
    await expect(
      validateWebhookTarget('https://10.0.0.1/hook'),
    ).rejects.toBeInstanceOf(WebhookTargetBlockedError);
  });

  it('allows a safe public raw IP in the URL', async () => {
    // No DNS mock needed — raw IP path doesn't call lookup.
    await expect(
      validateWebhookTarget('https://1.1.1.1/hook'),
    ).resolves.toMatchObject({ hostname: '1.1.1.1', resolvedIps: ['1.1.1.1'] });
  });

  // ---- DNS-based checks ----------------------------------------------------

  it('resolves a public hostname and returns it', async () => {
    mockDnsResolve('93.184.216.34'); // example.com public IP
    const result = await validateWebhookTarget('https://example.com/hook');
    expect(result.hostname).toBe('example.com');
    expect(result.resolvedIps).toContain('93.184.216.34');
  });

  it('throws WebhookTargetBlockedError when hostname resolves to 127.0.0.1', async () => {
    mockDnsResolve('127.0.0.1');
    const err = await validateWebhookTarget('https://evil.internal/hook').catch(
      (e) => e,
    );
    expect(err).toBeInstanceOf(WebhookTargetBlockedError);
    expect((err as WebhookTargetBlockedError).resolvedIp).toBe('127.0.0.1');
  });

  it('throws WebhookTargetBlockedError when hostname resolves to metadata IP', async () => {
    mockDnsResolve('169.254.169.254');
    await expect(
      validateWebhookTarget('https://metadata.evil.com/'),
    ).rejects.toBeInstanceOf(WebhookTargetBlockedError);
  });

  it('throws WebhookTargetBlockedError when hostname resolves to private RFC1918 IP', async () => {
    mockDnsResolve('10.0.0.1');
    await expect(
      validateWebhookTarget('https://internal.corp/hook'),
    ).rejects.toBeInstanceOf(WebhookTargetBlockedError);
  });

  it('rejects when ANY of multiple resolved IPs is blocked (mixed)', async () => {
    // One public, one blocked — must still reject (fail-closed).
    mockDnsResolveMany(['93.184.216.34', '192.168.1.1']);
    await expect(
      validateWebhookTarget('https://mixed.example.com/hook'),
    ).rejects.toBeInstanceOf(WebhookTargetBlockedError);
  });

  it('throws InvalidWebhookUrlError when DNS resolution fails', async () => {
    mockDnsFail('ENOTFOUND notexist.example.com');
    await expect(
      validateWebhookTarget('https://notexist.example.com/hook'),
    ).rejects.toBeInstanceOf(InvalidWebhookUrlError);
  });

  // ---- DNS-rebinding scenario (the core protection) -----------------------

  it('rejects a hostname that previously had a safe IP but now resolves to an internal IP (DNS-rebinding)', async () => {
    // Simulate DNS rebinding: the hostname is a valid-looking external domain
    // but at delivery time it resolves to an internal address.
    mockDnsResolve('172.16.0.1');
    await expect(
      validateWebhookTarget('https://rebind.attacker.com/hook'),
    ).rejects.toBeInstanceOf(WebhookTargetBlockedError);
  });

  // ---- Error message content -----------------------------------------------

  it('error message includes the hostname and resolved IP', async () => {
    mockDnsResolve('127.0.0.1');
    const err = await validateWebhookTarget('https://ssrf-target.example.com/hook').catch(
      (e) => e,
    );
    expect(err).toBeInstanceOf(WebhookTargetBlockedError);
    const message = (err as WebhookTargetBlockedError).message;
    expect(message).toContain('ssrf-target.example.com');
    expect(message).toContain('127.0.0.1');
  });

  it('WebhookTargetBlockedError has name "WebhookTargetBlockedError"', async () => {
    mockDnsResolve('127.0.0.1');
    const err = await validateWebhookTarget('https://x.example.com/').catch(
      (e) => e,
    );
    expect((err as Error).name).toBe('WebhookTargetBlockedError');
  });

  it('InvalidWebhookUrlError has name "InvalidWebhookUrlError"', async () => {
    await expect(
      validateWebhookTarget('http://example.com/'),
    ).rejects.toMatchObject({ name: 'InvalidWebhookUrlError' });
  });
});
