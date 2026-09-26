/**
 * Swap asset whitelist resolution.
 *
 * The authoritative list of assets that may be swapped FROM lives on the
 * backend and is delivered to the app through the session bootstrap runtime
 * config (see `BootstrapResponse.swappableAssets`). Sourcing it at runtime
 * means the backend can add an asset without shipping a new app release.
 *
 * This module resolves that runtime value, falling back to a conservative
 * built-in default when the config is unavailable or malformed.
 *
 * The asset codes used here are grounded in the verified-assets registry
 * (`services/verified-assets.ts`), which is the single source of truth for
 * the issuer-to-code mapping shared with path-payment.ts.
 */
import { isVerifiedAsset } from "./verified-assets";

/**
 * Conservative built-in default whitelist.
 *
 * XLM is always safe (native). USDC is the only non-native asset included
 * in the minimal fallback because it is verified in the asset registry and
 * has deep liquidity. All other verified assets are intentionally omitted
 * from the fallback so that, absent fresh runtime config, the app degrades
 * safely rather than offering swaps the backend may reject.
 */
export const DEFAULT_SWAPPABLE_ASSETS: readonly string[] = ["XLM", "USDC"];

/**
 * Resolves the swap asset whitelist from the runtime config bootstrap.
 *
 * Returns the config-supplied list when it is a non-empty array of valid asset
 * codes. Otherwise logs a warning and returns a copy of the conservative
 * built-in default.
 */
export function resolveSwappableAssets(configAssets?: string[] | null): string[] {
  if (Array.isArray(configAssets)) {
    const cleaned = configAssets.filter(
      (asset): asset is string => typeof asset === "string" && asset.trim().length > 0,
    );
    if (cleaned.length > 0) {
      return cleaned;
    }
  }

  console.warn(
    "[swappable-assets] Runtime config did not supply a swap asset whitelist; " +
      `falling back to built-in default: ${DEFAULT_SWAPPABLE_ASSETS.join(", ")}`,
  );
  return [...DEFAULT_SWAPPABLE_ASSETS];
}

/**
 * Returns true when the given asset code is present in the resolved whitelist.
 */
export function isAssetSwappable(asset: string, whitelist: string[]): boolean {
  return whitelist.includes(asset);
}
