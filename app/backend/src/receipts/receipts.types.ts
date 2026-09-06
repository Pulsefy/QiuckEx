import { NormalizedReceipt } from './schemas/receipt.schema';

export type ReceiptNetwork = 'testnet' | 'mainnet';

export interface PersistedReceipt {
  txHash: string;
  operationIndex: number;
  network: ReceiptNetwork;
  receipt: NormalizedReceipt;
  createdAt: Date;
  updatedAt: Date;
}
