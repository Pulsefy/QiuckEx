export type StellarNetwork = "testnet" | "mainnet";

/** Supported wallet providers */
export type WalletType = "freighter" | "lobstr" | "xbull" | "albedo" | "demo";

/** Edge-case errors that can occur during wallet operations */
export type WalletErrorCode =
  | "wallet_locked"
  | "wrong_network"
  | "signature_rejected"
  | "connection_failed"
  | "session_expired"
  | "wallet_not_found";

export interface WalletError {
  code: WalletErrorCode;
  message: string;
  recoverable: boolean;
}

export interface WalletState {
  connected: boolean;
  publicKey?: string;
  network: StellarNetwork;
  walletType?: WalletType;
  connectedAt?: number;
  error?: WalletError;
  isRestoring?: boolean;
}

/** Shape returned by the wallet context / useWallet hook */
export interface WalletContextValue {
  wallet: WalletState;
  connect: (walletType: WalletType, network?: StellarNetwork) => Promise<void>;
  disconnect: () => Promise<void>;
  switchAccount: (newPublicKey: string) => Promise<void>;
  switchNetwork: (network: StellarNetwork) => void;
  clearError: () => void;
}
