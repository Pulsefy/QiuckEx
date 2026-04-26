export type RefundableEntityType = 'payment' | 'escrow' | 'link';

export type RefundStatus = 'pending' | 'approved' | 'rejected' | 'failed';

export type RefundReasonCode =
  | 'DUPLICATE'
  | 'FRAUD'
  | 'CUSTOMER_REQUEST'
  | 'TECHNICAL_ERROR';

export interface RefundAttemptRecord {
  id: string;
  idempotency_key: string;
  entity_type: RefundableEntityType;
  entity_id: string;
  reason_code: RefundReasonCode;
  notes: string | null;
  status: RefundStatus;
  actor_id: string;
  created_at: string;
  updated_at: string;
}

export interface RefundAuditRecord {
  id: string;
  refund_id: string;
  actor_id: string;
  action: string;
  reason_code: RefundReasonCode | null;
  notes: string | null;
  created_at: string;
}
