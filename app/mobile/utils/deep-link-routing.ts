import { parsePaymentLink } from './parse-payment-link';

const QUICKEX_HOSTS = ['quickex.to', 'www.quickex.to'];
const QUICKEX_SCHEME = 'quickex';

export interface DeepLinkRoute {
  pathname: string;
  params: Record<string, string>;
}

export type DeepLinkResolution =
  | { route: DeepLinkRoute }
  | { error: string }
  | { ignored: true };

export function parseTransactionDeepLink(
  raw: string,
): { id: string; params: Record<string, string> } | null {
  try {
    const url = new URL(raw);

    if (url.protocol === `${QUICKEX_SCHEME}:`) {
      const segments = url.pathname
        .replace(/^\/+/, '')
        .split('/')
        .filter(Boolean);
      if (segments.length >= 2 && segments[0] === 'transaction') {
        const params: Record<string, string> = {};
        url.searchParams.forEach((value, key) => {
          params[key] = value;
        });
        return { id: segments[1], params };
      }
    }

    if (
      (url.protocol === 'https:' || url.protocol === 'http:') &&
      QUICKEX_HOSTS.includes(url.hostname)
    ) {
      const segments = url.pathname
        .replace(/^\/+/, '')
        .split('/')
        .filter(Boolean);
      if (segments.length >= 2 && segments[0] === 'transaction') {
        const params: Record<string, string> = {};
        url.searchParams.forEach((value, key) => {
          params[key] = value;
        });
        return { id: segments[1], params };
      }
    }
  } catch {
    return null;
  }
  return null;
}

export function isQuickExLink(raw: string): boolean {
  try {
    const url = new URL(raw);
    return (
      url.protocol === `${QUICKEX_SCHEME}:` ||
      ((url.protocol === 'https:' || url.protocol === 'http:') &&
        QUICKEX_HOSTS.includes(url.hostname))
    );
  } catch {
    return false;
  }
}

function looksLikePaymentLink(raw: string): boolean {
  try {
    const url = new URL(raw);

    if (url.protocol === `${QUICKEX_SCHEME}:`) {
      const segments = url.pathname.replace(/^\/+/, '').split('/').filter(Boolean);
      return segments.length === 0 || segments[0] !== 'transaction';
    }

    if ((url.protocol === 'https:' || url.protocol === 'http:') && QUICKEX_HOSTS.includes(url.hostname)) {
      const segments = url.pathname.replace(/^\/+/, '').split('/').filter(Boolean);
      return segments.length === 0 || segments[0] !== 'transaction';
    }

    return false;
  } catch {
    return false;
  }
}

export function resolveDeepLink(raw: string): DeepLinkResolution {
  const trimmed = raw.trim();
  if (!trimmed) {
    return { ignored: true };
  }

  const paymentResult = parsePaymentLink(trimmed);
  if (paymentResult.valid) {
    return {
      route: {
        pathname: '/payment-confirmation',
        params: {
          username: paymentResult.data.username,
          amount: paymentResult.data.amount,
          asset: paymentResult.data.asset,
          ...(paymentResult.data.memo ? { memo: paymentResult.data.memo } : {}),
          privacy: String(paymentResult.data.privacy),
        },
      },
    };
  }

  const transactionResult = parseTransactionDeepLink(trimmed);
  if (transactionResult) {
    return {
      route: {
        pathname: '/transaction/[id]',
        params: {
          id: transactionResult.id,
          ...transactionResult.params,
        },
      },
    };
  }

  if (isQuickExLink(trimmed)) {
    return {
      error: looksLikePaymentLink(trimmed)
        ? paymentResult.error ?? 'Unsupported or expired QuickEx link.'
        : 'Unsupported or expired QuickEx link.',
    };
  }

  return { ignored: true };
}
