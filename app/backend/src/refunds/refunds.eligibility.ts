import { PaymentDbStatus } from '../reconciliation/types/reconciliation.types';
import { EscrowDbStatus } from '../reconciliation/types/reconciliation.types';
import { LinkState } from '../links/link-state-machine';

export function isPaymentRefundable(status: PaymentDbStatus): boolean {
  return status === PaymentDbStatus.Paid;
}

export function isEscrowRefundable(status: EscrowDbStatus): boolean {
  return status === EscrowDbStatus.Active || status === EscrowDbStatus.Claimed;
}

export function isLinkRefundable(state: LinkState): boolean {
  return state === LinkState.PAID;
}
