import { PaymentDbStatus } from '../reconciliation/types/reconciliation.types';
import { EscrowDbStatus } from '../reconciliation/types/reconciliation.types';
import { LinkState } from '../links/link-state-machine';
import { EligibilityCheckResult } from './refunds.types';

export function isPaymentRefundable(status: PaymentDbStatus): boolean {
  return status === PaymentDbStatus.Paid;
}

export function isEscrowRefundable(status: EscrowDbStatus): boolean {
  return status === EscrowDbStatus.Active || status === EscrowDbStatus.Claimed;
}

export function isLinkRefundable(state: LinkState): boolean {
  return state === LinkState.PAID;
}

/**
 * Check if an entity is eligible for refund based on state
 */
export function checkPaymentEligibility(
  payment: { status: PaymentDbStatus; created_at: string } | null,
  maxAgeInDays: number = 90,
): EligibilityCheckResult {
  if (!payment) {
    return {
      eligible: false,
      reasonCode: 'ENTITY_NOT_FOUND',
      message: 'Payment not found',
    };
  }

  // Check age
  const ageInDays = (Date.now() - new Date(payment.created_at).getTime()) / (1000 * 60 * 60 * 24);
  if (ageInDays > maxAgeInDays) {
    return {
      eligible: false,
      reasonCode: 'TOO_OLD',
      message: `Payment is too old for refund (${Math.floor(ageInDays)} days old, max ${maxAgeInDays} days)`,
      details: {
        ageInDays: Math.floor(ageInDays),
        maxAgeInDays,
      },
    };
  }

  // Check state
  if (!isPaymentRefundable(payment.status)) {
    return {
      eligible: false,
      reasonCode: 'INVALID_STATE',
      message: `Payment is in ${payment.status} state, must be ${PaymentDbStatus.Paid}`,
      details: {
        currentState: payment.status,
      },
    };
  }

  return {
    eligible: true,
    reasonCode: 'ELIGIBLE',
    message: 'Payment is eligible for refund',
    details: {
      currentState: payment.status,
      ageInDays: Math.floor(ageInDays),
      maxAgeInDays,
    },
  };
}

export function checkEscrowEligibility(
  escrow: { status: EscrowDbStatus; created_at: string } | null,
  maxAgeInDays: number = 90,
): EligibilityCheckResult {
  if (!escrow) {
    return {
      eligible: false,
      reasonCode: 'ENTITY_NOT_FOUND',
      message: 'Escrow not found',
    };
  }

  // Check age
  const ageInDays = (Date.now() - new Date(escrow.created_at).getTime()) / (1000 * 60 * 60 * 24);
  if (ageInDays > maxAgeInDays) {
    return {
      eligible: false,
      reasonCode: 'TOO_OLD',
      message: `Escrow is too old for refund (${Math.floor(ageInDays)} days old, max ${maxAgeInDays} days)`,
      details: {
        ageInDays: Math.floor(ageInDays),
        maxAgeInDays,
      },
    };
  }

  // Check state
  if (!isEscrowRefundable(escrow.status)) {
    return {
      eligible: false,
      reasonCode: 'INVALID_STATE',
      message: `Escrow is in ${escrow.status} state, must be ${EscrowDbStatus.Active} or ${EscrowDbStatus.Claimed}`,
      details: {
        currentState: escrow.status,
      },
    };
  }

  return {
    eligible: true,
    reasonCode: 'ELIGIBLE',
    message: 'Escrow is eligible for refund',
    details: {
      currentState: escrow.status,
      ageInDays: Math.floor(ageInDays),
      maxAgeInDays,
    },
  };
}

export function checkLinkEligibility(
  link: { state: LinkState; created_at: string } | null,
  maxAgeInDays: number = 90,
): EligibilityCheckResult {
  if (!link) {
    return {
      eligible: false,
      reasonCode: 'ENTITY_NOT_FOUND',
      message: 'Link not found',
    };
  }

  // Check if already refunded first
  if (link.state === LinkState.REFUNDED) {
    return {
      eligible: false,
      reasonCode: 'ALREADY_REFUNDED',
      message: 'Link has already been refunded',
      details: {
        currentState: link.state,
      },
    };
  }

  // Check age
  const ageInDays = (Date.now() - new Date(link.created_at).getTime()) / (1000 * 60 * 60 * 24);
  if (ageInDays > maxAgeInDays) {
    return {
      eligible: false,
      reasonCode: 'TOO_OLD',
      message: `Link is too old for refund (${Math.floor(ageInDays)} days old, max ${maxAgeInDays} days)`,
      details: {
        ageInDays: Math.floor(ageInDays),
        maxAgeInDays,
      },
    };
  }

  // Check state
  if (!isLinkRefundable(link.state)) {
    return {
      eligible: false,
      reasonCode: 'INVALID_STATE',
      message: `Link is in ${link.state} state, must be ${LinkState.PAID}`,
      details: {
        currentState: link.state,
      },
    };
  }

  return {
    eligible: true,
    reasonCode: 'ELIGIBLE',
    message: 'Link is eligible for refund',
    details: {
      currentState: link.state,
      ageInDays: Math.floor(ageInDays),
      maxAgeInDays,
    },
  };
}
