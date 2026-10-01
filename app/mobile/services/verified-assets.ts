/**
 * Verified asset registry – the single source of truth for swappable,
 * non-native Stellar assets recognised by QiuckEx.
 *
 * Each entry pairs an asset code with its canonical on-chain issuer address.
 * Both `path-payment.ts` (for building Stellar operations) and
 * `swappable-assets.ts` (for UI whitelisting) derive their data from here,
 * ensuring the two subsystems can never diverge.
 *
 * To add a new asset: append an entry to VERIFIED_ASSETS and it will
 * automatically become available for swaps and path payments without any
 * further code changes.
 */

export interface VerifiedAsset {
  /** Stellar asset code, e.g. "USDC". */
  code: string;
  /** Canonical issuer account ID for this asset. */
  issuer: string;
  /** Human-readable display name (optional, for UI). */
  name?: string;
}

/**
 * Authoritative list of verified, swappable non-native assets.
 *
 * Issuers are taken from Stellar Expert / the official asset anchors and
 * must not be changed without a corresponding on-chain verification step.
 */
export const VERIFIED_ASSETS: readonly VerifiedAsset[] = [
  {
    code: "USDC",
    issuer: "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN",
    name: "USD Coin",
  },
  {
    code: "AQUA",
    issuer: "GBNZILSTVQZ4R7IKQDGHYGY2QXL5QOFJYQMXPKWRRM5PAV7Y4M67AQUA",
    name: "Aquarius",
  },
  {
    code: "yXLM",
    issuer: "GARDNV3Q7YGT4AKSDF25LT32YSCCW4EV22Y2TV3I2PU2MMXJTEDL5T55",
    name: "yield XLM",
  },
];

/**
 * A pre-built lookup map (code → VerifiedAsset) for O(1) issuer resolution.
 * Keys are upper-cased to allow case-insensitive lookups.
 */
export const VERIFIED_ASSET_MAP: ReadonlyMap<string, VerifiedAsset> = new Map(
  VERIFIED_ASSETS.map((asset) => [asset.code.toUpperCase(), asset]),
);

/**
 * Returns the verified issuer for the given asset code, or `undefined` when
 * the code is not in the registry.
 *
 * @param code - Asset code, e.g. "USDC" (case-insensitive).
 */
export function getVerifiedIssuer(code: string): string | undefined {
  return VERIFIED_ASSET_MAP.get(code.trim().toUpperCase())?.issuer;
}

/**
 * Returns true when `code` has a verified entry in the registry.
 *
 * @param code - Asset code (case-insensitive).
 */
export function isVerifiedAsset(code: string): boolean {
  return VERIFIED_ASSET_MAP.has(code.trim().toUpperCase());
}

/**
 * Returns all verified asset codes as an array of strings.
 * Useful for initialising the swappable-assets whitelist from the registry.
 */
export function getVerifiedAssetCodes(): string[] {
  return VERIFIED_ASSETS.map((a) => a.code);
}
