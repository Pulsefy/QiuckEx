/**
 * useWallet — convenience wrapper around WalletContext.
 *
 * Components that need wallet state should call this hook instead of
 * importing the context directly. It re-exports the full WalletContextValue
 * so the API surface stays identical whether you use the hook or the context.
 */
import { useWalletContext } from "./useWalletContext";

export type { WalletContextValue, WalletState, WalletType, WalletError } from "../types/wallet";

export function useWallet() {
  return useWalletContext();
}
