export type StellarNetwork = "testnet" | "mainnet";

export interface WalletState {
  connected: boolean;
  publicKey?: string;
  network: StellarNetwork;
}