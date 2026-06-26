import { PaymentDbStatus, EscrowDbStatus } from '../reconciliation/types/reconciliation.types';
import { LinkState } from '../links/link-state-machine';
import {
  checkPaymentEligibility,
  checkEscrowEligibility,
  checkLinkEligibility,
} from './refunds.eligibility';

describe('Refund Eligibility', () => {
  const now = new Date();
  const recentDate = new Date(now.getTime() - 10 * 24 * 60 * 60 * 1000); // 10 days ago
  const oldDate = new Date(now.getTime() - 100 * 24 * 60 * 60 * 1000); // 100 days ago

  describe('checkPaymentEligibility', () => {
    it('should return eligible for recent paid payment', () => {
      const result = checkPaymentEligibility(
        { status: PaymentDbStatus.Paid, created_at: recentDate.toISOString() },
        90,
      );

      expect(result.eligible).toBe(true);
      expect(result.reasonCode).toBe('ELIGIBLE');
      expect(result.message).toBe('Payment is eligible for refund');
      expect(result.details?.currentState).toBe(PaymentDbStatus.Paid);
      expect(result.details?.ageInDays).toBeLessThan(90);
    });

    it('should return not eligible if payment not found', () => {
      const result = checkPaymentEligibility(null, 90);

      expect(result.eligible).toBe(false);
      expect(result.reasonCode).toBe('ENTITY_NOT_FOUND');
      expect(result.message).toBe('Payment not found');
    });

    it('should return not eligible if payment is too old', () => {
      const result = checkPaymentEligibility(
        { status: PaymentDbStatus.Paid, created_at: oldDate.toISOString() },
        90,
      );

      expect(result.eligible).toBe(false);
      expect(result.reasonCode).toBe('TOO_OLD');
      expect(result.message).toContain('too old for refund');
      expect(result.details?.ageInDays).toBeGreaterThan(90);
      expect(result.details?.maxAgeInDays).toBe(90);
    });

    it('should return not eligible if payment is in wrong state', () => {
      const result = checkPaymentEligibility(
        { status: PaymentDbStatus.Pending, created_at: recentDate.toISOString() },
        90,
      );

      expect(result.eligible).toBe(false);
      expect(result.reasonCode).toBe('INVALID_STATE');
      expect(result.message).toContain('must be paid');
      expect(result.details?.currentState).toBe(PaymentDbStatus.Pending);
    });

    it('should reject failed payment', () => {
      const result = checkPaymentEligibility(
        { status: PaymentDbStatus.Failed, created_at: recentDate.toISOString() },
        90,
      );

      expect(result.eligible).toBe(false);
      expect(result.reasonCode).toBe('INVALID_STATE');
    });

    it('should reject processing payment', () => {
      const result = checkPaymentEligibility(
        { status: PaymentDbStatus.Processing, created_at: recentDate.toISOString() },
        90,
      );

      expect(result.eligible).toBe(false);
      expect(result.reasonCode).toBe('INVALID_STATE');
    });
  });

  describe('checkEscrowEligibility', () => {
    it('should return eligible for recent active escrow', () => {
      const result = checkEscrowEligibility(
        { status: EscrowDbStatus.Active, created_at: recentDate.toISOString() },
        90,
      );

      expect(result.eligible).toBe(true);
      expect(result.reasonCode).toBe('ELIGIBLE');
      expect(result.message).toBe('Escrow is eligible for refund');
      expect(result.details?.currentState).toBe(EscrowDbStatus.Active);
    });

    it('should return eligible for recent claimed escrow', () => {
      const result = checkEscrowEligibility(
        { status: EscrowDbStatus.Claimed, created_at: recentDate.toISOString() },
        90,
      );

      expect(result.eligible).toBe(true);
      expect(result.reasonCode).toBe('ELIGIBLE');
      expect(result.details?.currentState).toBe(EscrowDbStatus.Claimed);
    });

    it('should return not eligible if escrow not found', () => {
      const result = checkEscrowEligibility(null, 90);

      expect(result.eligible).toBe(false);
      expect(result.reasonCode).toBe('ENTITY_NOT_FOUND');
      expect(result.message).toBe('Escrow not found');
    });

    it('should return not eligible if escrow is too old', () => {
      const result = checkEscrowEligibility(
        { status: EscrowDbStatus.Active, created_at: oldDate.toISOString() },
        90,
      );

      expect(result.eligible).toBe(false);
      expect(result.reasonCode).toBe('TOO_OLD');
      expect(result.message).toContain('too old for refund');
      expect(result.details?.ageInDays).toBeGreaterThan(90);
    });

    it('should return not eligible if escrow is pending', () => {
      const result = checkEscrowEligibility(
        { status: EscrowDbStatus.Pending, created_at: recentDate.toISOString() },
        90,
      );

      expect(result.eligible).toBe(false);
      expect(result.reasonCode).toBe('INVALID_STATE');
      expect(result.message).toContain('must be active or claimed');
      expect(result.details?.currentState).toBe(EscrowDbStatus.Pending);
    });

    it('should reject expired escrow', () => {
      const result = checkEscrowEligibility(
        { status: EscrowDbStatus.Expired, created_at: recentDate.toISOString() },
        90,
      );

      expect(result.eligible).toBe(false);
      expect(result.reasonCode).toBe('INVALID_STATE');
    });

    it('should reject cancelled escrow', () => {
      const result = checkEscrowEligibility(
        { status: EscrowDbStatus.Cancelled, created_at: recentDate.toISOString() },
        90,
      );

      expect(result.eligible).toBe(false);
      expect(result.reasonCode).toBe('INVALID_STATE');
    });
  });

  describe('checkLinkEligibility', () => {
    it('should return eligible for recent paid link', () => {
      const result = checkLinkEligibility(
        { state: LinkState.PAID, created_at: recentDate.toISOString() },
        90,
      );

      expect(result.eligible).toBe(true);
      expect(result.reasonCode).toBe('ELIGIBLE');
      expect(result.message).toBe('Link is eligible for refund');
      expect(result.details?.currentState).toBe(LinkState.PAID);
    });

    it('should return not eligible if link not found', () => {
      const result = checkLinkEligibility(null, 90);

      expect(result.eligible).toBe(false);
      expect(result.reasonCode).toBe('ENTITY_NOT_FOUND');
      expect(result.message).toBe('Link not found');
    });

    it('should return not eligible if link is too old', () => {
      const result = checkLinkEligibility(
        { state: LinkState.PAID, created_at: oldDate.toISOString() },
        90,
      );

      expect(result.eligible).toBe(false);
      expect(result.reasonCode).toBe('TOO_OLD');
      expect(result.message).toContain('too old for refund');
      expect(result.details?.ageInDays).toBeGreaterThan(90);
    });

    it('should return not eligible if link is in draft state', () => {
      const result = checkLinkEligibility(
        { state: LinkState.DRAFT, created_at: recentDate.toISOString() },
        90,
      );

      expect(result.eligible).toBe(false);
      expect(result.reasonCode).toBe('INVALID_STATE');
      expect(result.message).toContain('must be PAID');
      expect(result.details?.currentState).toBe(LinkState.DRAFT);
    });

    it('should return not eligible if link is already refunded', () => {
      const result = checkLinkEligibility(
        { state: LinkState.REFUNDED, created_at: recentDate.toISOString() },
        90,
      );

      expect(result.eligible).toBe(false);
      expect(result.reasonCode).toBe('ALREADY_REFUNDED');
      expect(result.message).toBe('Link has already been refunded');
      expect(result.details?.currentState).toBe(LinkState.REFUNDED);
    });

    it('should reject active link', () => {
      const result = checkLinkEligibility(
        { state: LinkState.ACTIVE, created_at: recentDate.toISOString() },
        90,
      );

      expect(result.eligible).toBe(false);
      expect(result.reasonCode).toBe('INVALID_STATE');
    });

    it('should reject expired link', () => {
      const result = checkLinkEligibility(
        { state: LinkState.EXPIRED, created_at: recentDate.toISOString() },
        90,
      );

      expect(result.eligible).toBe(false);
      expect(result.reasonCode).toBe('INVALID_STATE');
    });
  });

  describe('Age boundary tests', () => {
    it('should allow payment just under 90 days', () => {
      const almostNinetyDays = new Date(now.getTime() - (89.9 * 24 * 60 * 60 * 1000));
      const result = checkPaymentEligibility(
        { status: PaymentDbStatus.Paid, created_at: almostNinetyDays.toISOString() },
        90,
      );

      expect(result.eligible).toBe(true);
      expect(result.reasonCode).toBe('ELIGIBLE');
    });

    it('should reject payment at 91 days', () => {
      const ninetyOneDays = new Date(now.getTime() - 91 * 24 * 60 * 60 * 1000);
      const result = checkPaymentEligibility(
        { status: PaymentDbStatus.Paid, created_at: ninetyOneDays.toISOString() },
        90,
      );

      expect(result.eligible).toBe(false);
      expect(result.reasonCode).toBe('TOO_OLD');
    });
  });
});
