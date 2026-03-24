/**
 * Curated list of assets allowed in the link generator (aligned with links whitelist + issuers).
 */
export type VerifiedAssetRecord = {
  code: string;
  type: 'native' | 'credit_alphanum4' | 'credit_alphanum12';
  issuer: string | null;
  verified: true;
  decimals: number;
};

export const VERIFIED_STELLAR_ASSETS: readonly VerifiedAssetRecord[] = [
  {
    code: 'XLM',
    type: 'native',
    issuer: null,
    verified: true,
    decimals: 7,
  },
  {
    code: 'USDC',
    type: 'credit_alphanum4',
    issuer:
      'GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN',
    verified: true,
    decimals: 7,
  },
  {
    code: 'AQUA',
    type: 'credit_alphanum4',
    issuer:
      'GBNZILSTVQZ4R7IKQDGHYGY2QXL5QOFJYQMXPKWRRM5PAV7Y4M67AQUA',
    verified: true,
    decimals: 7,
  },
  {
    code: 'yXLM',
    type: 'credit_alphanum4',
    issuer:
      'GARDNV3Q7YGT4AKSDF25LT32YSCCW4EV22Y2TV3I2PU2MMXJTEDL5T55',
    verified: true,
    decimals: 7,
  },
] as const;

export function findVerifiedAsset(code: string): VerifiedAssetRecord | undefined {
  const t = code.trim().toLowerCase();
  return VERIFIED_STELLAR_ASSETS.find(
    (a) => a.code.toLowerCase() === t,
  );
}
