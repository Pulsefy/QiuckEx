export const PUSH_NOTIFICATION_TYPES = {
  transactionDetail: "transaction_detail",
  escrowDetail: "escrow_detail",
  listingDetail: "listing_detail",
} as const;

export type PushNotificationType =
  (typeof PUSH_NOTIFICATION_TYPES)[keyof typeof PUSH_NOTIFICATION_TYPES];

type BasePayload = {
  type: PushNotificationType;
};

export type TransactionDetailNotificationPayload = BasePayload & {
  type: typeof PUSH_NOTIFICATION_TYPES.transactionDetail;
  transactionId: string;
  txHash?: string;
  amount?: string;
  asset?: string;
  status?: string;
};

export type EscrowDetailNotificationPayload = BasePayload & {
  type: typeof PUSH_NOTIFICATION_TYPES.escrowDetail;
  escrowId: string;
  status?: string;
};

export type ListingDetailNotificationPayload = BasePayload & {
  type: typeof PUSH_NOTIFICATION_TYPES.listingDetail;
  listingId: string;
  sellerId?: string;
};

export type PushNotificationPayload =
  | TransactionDetailNotificationPayload
  | EscrowDetailNotificationPayload
  | ListingDetailNotificationPayload;
