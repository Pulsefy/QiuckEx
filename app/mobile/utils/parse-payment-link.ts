const QUICKEX_HOSTS = ['quickex.to', 'www.quickex.to'];
const QUICKEX_SCHEME = 'quickex';

const ASSET_WHITELIST = ['XLM', 'USDC', 'AQUA', 'yXLM'] as const;
type AssetCode = (typeof ASSET_WHITELIST)[number];

const AMOUNT_MIN = 0.0000001;
const AMOUNT_MAX = 1_000_000;
const MEMO_MAX_LENGTH = 28;
const USERNAME_PATTERN = /^[a-z0-9_]{3,32}$/;

export interface PaymentLinkData {
  username: string;
  amount: string;
  asset: AssetCode;
  memo: string | null;
  privacy: boolean;
}

export type ParseResult =
  | { valid: true; data: PaymentLinkData }
  | { valid: false; error: string };

function extractParts(raw: string): { username: string; params: URLSearchParams } | null {
  try {
    const url = new URL(raw);

    if (url.protocol === `${QUICKEX_SCHEME}:`) {
      // quickex://username?amount=...  –  hostname holds the username
      const username = url.hostname || url.pathname.replace(/^\/+/, '').split('/')[0];
      return username ? { username, params: url.searchParams } : null;
    }

    if ((url.protocol === 'https:' || url.protocol === 'http:') && QUICKEX_HOSTS.includes(url.hostname)) {
      const segments = url.pathname.replace(/^\/+/, '').split('/').filter(Boolean);
      if (segments.length === 0) return null;
      return { username: segments[0], params: url.searchParams };
    }
  } catch {
    // not a valid URL
  }
  return null;
}

export function parsePaymentLink(raw: string): ParseResult {
  const trimmed = raw.trim();
  if (!trimmed) {
    return { valid: false, error: 'Empty link' };
  }

  const parts = extractParts(trimmed);
  if (!parts) {
    return { valid: false, error: 'Not a valid QuickEx link' };
  }

  const { username, params } = parts;

  if (!USERNAME_PATTERN.test(username)) {
    return { valid: false, error: `Invalid username "${username}"` };
  }

  const rawAmount = params.get('amount');
  if (!rawAmount) {
    return { valid: false, error: 'Missing amount' };
  }
  const amount = Number(rawAmount);
  if (Number.isNaN(amount) || amount < AMOUNT_MIN || amount > AMOUNT_MAX) {
    return { valid: false, error: `Amount must be between ${AMOUNT_MIN} and ${AMOUNT_MAX}` };
  }
  const formattedAmount = amount.toFixed(7);

  const rawAsset = (params.get('asset') ?? 'XLM').toUpperCase();
  if (!ASSET_WHITELIST.includes(rawAsset as AssetCode)) {
    return { valid: false, error: `Unsupported asset "${rawAsset}". Supported: ${ASSET_WHITELIST.join(', ')}` };
  }
  const asset = rawAsset as AssetCode;

  let memo: string | null = null;
  const rawMemo = params.get('memo');
  if (rawMemo) {
    const decoded = decodeURIComponent(rawMemo).trim();
    if (decoded.length > MEMO_MAX_LENGTH) {
      return { valid: false, error: `Memo exceeds ${MEMO_MAX_LENGTH} characters` };
    }
    if (decoded.length > 0) {
      memo = decoded;
    }
  }

  const privacy = params.get('privacy') === 'true';

  return {
    valid: true,
    data: { username, amount: formattedAmount, asset, memo, privacy },
  };
}
