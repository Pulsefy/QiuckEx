import { useState } from "react";
import { WalletState, StellarNetwork } from "../types/wallet";

export function useWallet() {
  const [wallet, setWallet] = useState<WalletState>({
    connected: false,
    publicKey: undefined,
    network: "testnet", // default
  });

  const connect = async () => {
    // TODO: Replace with real wallet integration
    setWallet({
      connected: true,
      // Use a valid testnet public key so we can trigger real testnet payments during demo
      publicKey: "GAMOSFOKEYHFDGMXIEFEYBUYK3ZMFYN3PFLOTBRXFGBFGRKBKLQSLGLP",
      network: "testnet",
    });
  };

  const disconnect = () => {
    setWallet({
      connected: false,
      publicKey: undefined,
      network: wallet.network,
    });
  };

  const toggleNetwork = () => {
    const newNetwork: StellarNetwork =
      wallet.network === "testnet" ? "mainnet" : "testnet";

    setWallet({
      ...wallet,
      network: newNetwork,
    });
  };

  return {
    wallet,
    connect,
    disconnect,
    toggleNetwork,
  };
}
