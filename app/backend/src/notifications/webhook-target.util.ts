/**
 * Shared webhook-target rules with SSRF protection.
 *
 * This module is deliberately a leaf: it imports nothing from the backend, so
 * both the API layer (`ExportsService`, which validates at request time) and
 * the background layer (`ExportGenerationHandler`, which picks the target at
 * delivery time) can depend on it without creating an import cycle.
 *
 * The two call sites MUST agree. If the API accepts a request because a valid
 * https target exists while the handler picks a different, non-https target,
 * a signed, time-limited download reference gets posted in cleartext.
 *
 * SSRF protection (#1219): hostname resolution and IP-range checks are shared
 * here so every caller — webhook registration, export delivery, contract-change
 * webhooks, developer test-webhook, and the job-queue delivery handler —
 * applies the same rule and the rule cannot drift between callers.
 */

import * as ipaddr from 'ipaddr.js';

/**
 * Cloud metadata endpoints and other link-local addresses that must never
 * receive outbound webhook traffic.
 *
 * 169.254.169.254 — AWS/GCP/Azure metadata endpoint
 * 169.254.170.2   — ECS task metadata endpoint
 * 100.64.0.0/10   — Shared carrier-grade NAT range
 * 0.0.0.0          — Unspecified address
 */
const BLOCKED_IP_RANGES: string[] = [
  // Loopback
  '127.0.0.0/8',
  '::1/128',
  // Private (RFC 1918)
  '10.0.0.0/8',
  '172.16.0.0/12',
  '192.168.0.0/16',
  // Link-local (includes cloud metadata 169.254.169.254)
  '169.254.0.0/16',
  'fe80::/10',
  // CGNAT
  '100.64.0.0/10',
  // Unspecified
  '0.0.0.0/8',
  '::/128',
  // Private IPv6 unique local addresses
  'fc00::/7',
  // IPv4-mapped IPv6 loopback/private
  // (ipaddr.js handles ::ffff:0:0/96 via IPv4 conversion, but we also
  //  check explicitly below for safety)
];

/**
 * Error thrown when a webhook URL resolves to a blocked IP range.
 */
export class WebhookTargetBlockedError extends Error {
  constructor(
    public readonly hostname: string,
    public readonly resolvedIp: string,
  ) {
    super(
      `Webhook target "${hostname}" resolves to a blocked IP address (${resolvedIp}). ` +
        'Loopback, private, link-local, and cloud-metadata addresses are not allowed.',
    );
    this.name = 'WebhookTargetBlockedError';
  }
}

/**
 * Error thrown when a webhook URL is invalid (not https, malformed, etc.).
 */
export class InvalidWebhookUrlError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'InvalidWebhookUrlError';
  }
}

/**
 * Whether a resolved IP address falls within a blocked range.
 *
 * Handles IPv4, IPv6, and IPv4-mapped IPv6 addresses. IPv4-mapped IPv6
 * addresses (::ffff:a.b.c.d) are converted to their IPv4 representation
 * before range-checking so that ::ffff:127.0.0.1 is treated the same as
 * 127.0.0.1.
 */
export function isBlockedIp(ipStr: string): boolean {
  let addr: ipaddr.IPv4 | ipaddr.IPv6;
  try {
    addr = ipaddr.parse(ipStr);
  } catch {
    // If we can't parse it, treat it as blocked (fail-closed).
    return true;
  }

  // Convert IPv4-mapped IPv6 addresses to their IPv4 representation.
  if (addr instanceof ipaddr.IPv6 && addr.isIPv4MappedAddress()) {
    const ipv4Bytes = addr.toIPv4Address().octets;
    addr = new ipaddr.IPv4(ipv4Bytes);
  }

  const ranges = BLOCKED_IP_RANGES;

  for (const range of ranges) {
    try {
      const [subnet, prefixStr] = range.split('/');
      const subnetAddr = ipaddr.parse(subnet);
      const prefix = parseInt(prefixStr, 10);

      if (subnetAddr.kind() !== addr.kind()) continue;

      if (addr.match([subnetAddr, prefix])) {
        return true;
      }
    } catch {
      // If a range fails to parse, skip it rather than failing open.
      continue;
    }
  }

  return false;
}

/**
 * Whether a registered webhook target can actually be delivered to.
 *
 * Only absolute https URLs qualify:
 * - `http` would leak the signed download reference in transit.
 * - A relative or malformed value cannot be delivered to at all.
 *
 * This is the **synchronous** protocol/format check only. For full SSRF
 * protection including DNS resolution and IP-range validation, use
 * {@link validateWebhookTarget} instead.
 */
export function isDeliverableWebhookUrl(
  webhookUrl: string | null | undefined,
): boolean {
  if (!webhookUrl) {
    return false;
  }

  try {
    return new URL(webhookUrl).protocol === 'https:';
  } catch {
    return false;
  }
}

/**
 * Resolve and validate a webhook target URL for SSRF safety.
 *
 * This is the **async** full validation that:
 * 1. Checks the URL is a well-formed https URL.
 * 2. Extracts the hostname and resolves it via DNS.
 * 3. Checks every resolved IP against blocked ranges (loopback, private,
 *    link-local, cloud-metadata, CGNAT, unspecified).
 * 4. Rejects raw-IP URLs that are already in blocked ranges (no DNS needed).
 *
 * Throws {@link InvalidWebhookUrlError} for protocol/format issues and
 * {@link WebhookTargetBlockedError} when the resolved IP is in a blocked range.
 *
 * @param webhookUrl - The URL to validate.
 * @throws {InvalidWebhookUrlError} If the URL is not a valid https URL.
 * @throws {WebhookTargetBlockedError} If the resolved IP is in a blocked range.
 */
export async function validateWebhookTarget(
  webhookUrl: string,
): Promise<{ hostname: string; resolvedIps: string[] }> {
  // 1. Parse and check protocol
  let parsed: URL;
  try {
    parsed = new URL(webhookUrl);
  } catch {
    throw new InvalidWebhookUrlError(`Invalid webhook URL: ${webhookUrl}`);
  }

  if (parsed.protocol !== 'https:') {
    throw new InvalidWebhookUrlError(
      `Webhook URL must use https protocol, got: ${parsed.protocol}`,
    );
  }

  const hostname = parsed.hostname;

  if (!hostname) {
    throw new InvalidWebhookUrlError('Webhook URL has no hostname');
  }

  // 2. If the hostname is already a raw IP, check it directly (no DNS needed).
  if (ipaddr.isValid(hostname)) {
    if (isBlockedIp(hostname)) {
      throw new WebhookTargetBlockedError(hostname, hostname);
    }
    return { hostname, resolvedIps: [hostname] };
  }

  // 3. Resolve the hostname via DNS and check every returned IP.
  let resolvedIps: string[];
  try {
    const { lookup } = await import('dns/promises');
    const result = await lookup(hostname, { all: true });
    resolvedIps = result.map((r) => r.address);

    if (resolvedIps.length === 0) {
      throw new InvalidWebhookUrlError(
        `Could not resolve hostname: ${hostname}`,
      );
    }
  } catch (error) {
    if (error instanceof InvalidWebhookUrlError) throw error;
    if (error instanceof WebhookTargetBlockedError) throw error;
    throw new InvalidWebhookUrlError(
      `Failed to resolve webhook hostname "${hostname}": ${
        error instanceof Error ? error.message : 'unknown error'
      }`,
    );
  }

  // 4. Check every resolved IP — if any is blocked, reject.
  for (const ip of resolvedIps) {
    if (isBlockedIp(ip)) {
      throw new WebhookTargetBlockedError(hostname, ip);
    }
  }

  return { hostname, resolvedIps };
}

/**
 * Synchronous wrapper that validates the URL format and protocol, and checks
 * raw-IP hostnames against blocked ranges, without doing a DNS lookup.
 *
 * Use this when you need a fast boolean check (e.g. in a filter predicate)
 * and full SSRF validation will be done later at delivery time.
 */
export function isWebhookUrlSafe(webhookUrl: string | null | undefined): boolean {
  if (!webhookUrl) return false;

  let parsed: URL;
  try {
    parsed = new URL(webhookUrl);
  } catch {
    return false;
  }

  if (parsed.protocol !== 'https:') return false;

  const hostname = parsed.hostname;
  if (!hostname) return false;

  // If it's a raw IP, check it now. Hostnames are checked at delivery time.
  if (ipaddr.isValid(hostname)) {
    return !isBlockedIp(hostname);
  }

  return true;
}
