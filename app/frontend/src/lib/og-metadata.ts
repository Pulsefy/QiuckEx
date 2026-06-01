/**
 * Shared utilities for building OpenGraph / social-preview metadata.
 *
 * Privacy rules enforced here:
 *  - destinationPublicKey  → never exposed
 *  - transactionHash       → never exposed
 *  - paidAt                → never exposed
 *  - swapOptions           → never exposed
 *  - memo                  → only included when it is a short, non-sensitive label
 */

export const SITE_NAME = "QuickEx";
export const SITE_DESCRIPTION = "Privacy-focused payments on Stellar";

/** Resolved at build/request time from the environment. Falls back to a relative path. */
export function getSiteUrl(): string {
  return (
    process.env.NEXT_PUBLIC_SITE_URL?.replace(/\/$/, "") ??
    process.env.NEXT_PUBLIC_QUICKEX_API_URL?.replace(/\/$/, "").replace(
      /:4000$/,
      ":3000",
    ) ??
    "https://quickex.to"
  );
}

/** The default OG image served from /public */
export const DEFAULT_OG_IMAGE = "/og-default.png";

/** Safe subset of payment-link status returned by the backend */
export interface SafePaymentMeta {
  username: string;
  amount: string;
  asset: string;
  /** Only included when it looks like a safe, human-readable label */
  memo?: string;
  state: "ACTIVE" | "EXPIRED" | "PAID" | "REFUNDED" | "DRAFT" | "UNKNOWN";
}

/**
 * Fetch only the fields we need for OG metadata.
 * Returns null on any error so callers can fall back gracefully.
 */
export async function fetchPaymentMeta(params: {
  username: string;
  amount: string;
  asset?: string;
  memo?: string;
  acceptedAssets?: string;
}): Promise<SafePaymentMeta | null> {
  try {
    const apiBase =
      process.env.QUICKEX_INTERNAL_API_URL?.replace(/\/$/, "") ??
      process.env.NEXT_PUBLIC_QUICKEX_API_URL?.replace(/\/$/, "") ??
      "http://localhost:4000";

    const qs = new URLSearchParams({ username: params.username, amount: params.amount });
    if (params.asset) qs.set("asset", params.asset);
    if (params.memo) qs.set("memo", params.memo);
    if (params.acceptedAssets) qs.set("acceptedAssets", params.acceptedAssets);

    const res = await fetch(`${apiBase}/payment-links/status?${qs.toString()}`, {
      headers: { Accept: "application/json" },
      // Don't cache stale state — but keep it fast with a short revalidation
      next: { revalidate: 30 },
    });

    if (!res.ok) return null;

    const data = await res.json();

    return {
      username: sanitizeText(data.username ?? params.username),
      amount: sanitizeAmount(data.amount ?? params.amount),
      asset: sanitizeAsset(data.asset ?? params.asset ?? "XLM"),
      memo: isSafeMemo(data.memo) ? sanitizeText(data.memo) : undefined,
      state: isValidState(data.state) ? data.state : "UNKNOWN",
    };
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Metadata builders
// ---------------------------------------------------------------------------

/** Build OG title for a payment link */
export function buildPaymentTitle(meta: SafePaymentMeta): string {
  switch (meta.state) {
    case "PAID":
      return `Payment to @${meta.username} — Completed`;
    case "EXPIRED":
      return `Payment to @${meta.username} — Expired`;
    case "REFUNDED":
      return `Payment to @${meta.username} — Refunded`;
    case "ACTIVE":
    case "DRAFT":
      return `Pay ${meta.amount} ${meta.asset} to @${meta.username}`;
    default:
      return `Payment link — QuickEx`;
  }
}

/** Build OG description for a payment link */
export function buildPaymentDescription(meta: SafePaymentMeta): string {
  const memoSuffix = meta.memo ? ` · ${meta.memo}` : "";

  switch (meta.state) {
    case "PAID":
      return `This payment of ${meta.amount} ${meta.asset} to @${meta.username} has been completed.${memoSuffix}`;
    case "EXPIRED":
      return `This payment link for @${meta.username} has expired. Create a new link to send ${meta.asset}.`;
    case "REFUNDED":
      return `This payment to @${meta.username} was refunded.${memoSuffix}`;
    case "ACTIVE":
    case "DRAFT":
      return `Send ${meta.amount} ${meta.asset} to @${meta.username} on the Stellar network.${memoSuffix}`;
    default:
      return SITE_DESCRIPTION;
  }
}

/** Fallback metadata for unknown / expired / invalid links */
export const FALLBACK_PAYMENT_METADATA = {
  title: `Payment Link — ${SITE_NAME}`,
  description:
    "This payment link is unavailable, expired, or invalid. Visit QuickEx to create a new one.",
  ogImage: DEFAULT_OG_IMAGE,
} as const;

// ---------------------------------------------------------------------------
// Sanitisation helpers — keep these strict
// ---------------------------------------------------------------------------

/** Strip anything that isn't alphanumeric, space, dash, underscore, dot, or # */
function sanitizeText(value: unknown): string {
  if (typeof value !== "string") return "";
  return value.replace(/[^\w\s\-_.#@]/g, "").slice(0, 64).trim();
}

/** Ensure amount is a valid decimal string */
function sanitizeAmount(value: unknown): string {
  if (typeof value !== "string" && typeof value !== "number") return "0";
  const num = parseFloat(String(value));
  if (isNaN(num) || num < 0) return "0";
  // Strip trailing zeros but keep up to 7 decimal places
  return num.toLocaleString("en-US", { maximumFractionDigits: 7 });
}

/** Ensure asset code is safe (letters/digits only, max 12 chars) */
function sanitizeAsset(value: unknown): string {
  if (typeof value !== "string") return "XLM";
  return value.replace(/[^A-Z0-9]/gi, "").slice(0, 12).toUpperCase() || "XLM";
}

/**
 * A memo is "safe" to show in a preview if:
 *  - it exists and is a non-empty string
 *  - it is ≤ 28 characters (Stellar memo limit)
 *  - it doesn't look like a Stellar public key or transaction hash
 */
function isSafeMemo(value: unknown): value is string {
  if (typeof value !== "string" || value.trim().length === 0) return false;
  if (value.length > 28) return false;
  // Reject anything that looks like a key or hash (long hex/base58 strings)
  if (/^[A-Z0-9]{32,}$/.test(value)) return false;
  return true;
}

function isValidState(value: unknown): value is SafePaymentMeta["state"] {
  return ["ACTIVE", "EXPIRED", "PAID", "REFUNDED", "DRAFT"].includes(
    value as string,
  );
}
