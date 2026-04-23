export interface PaymentNotification {
  id: string; // txHash or pagingToken
  amount: string;
  asset?: string;
  sender?: string;
  receivedAt: number; // epoch ms
  read: boolean;
  direction?: "incoming" | "outgoing";
  memo?: string;
  txHash?: string;
  pagingToken?: string;
}
