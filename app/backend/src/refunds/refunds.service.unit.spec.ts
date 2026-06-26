import { Test, TestingModule } from '@nestjs/testing';
import { ConflictException } from '@nestjs/common';
import { RefundsService } from './refunds.service';
import { SupabaseService } from '../supabase/supabase.service';
import { PaymentDbStatus, EscrowDbStatus } from '../reconciliation/types/reconciliation.types';
import { LinkState } from '../links/link-state-machine';

describe('RefundsService - Eligibility Endpoint', () => {
  let service: RefundsService;

  const mockClient = {
    from: jest.fn().mockReturnThis(),
    select: jest.fn().mockReturnThis(),
    eq: jest.fn().mockReturnThis(),
    in: jest.fn().mockReturnThis(),
    maybeSingle: jest.fn(),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        RefundsService,
        {
          provide: SupabaseService,
          useValue: {
            getClient: jest.fn(() => mockClient),
          },
        },
      ],
    }).compile();

    service = module.get<RefundsService>(RefundsService);

    jest.clearAllMocks();
  });

  describe('checkEligibility', () => {
    describe('Payment eligibility', () => {
      it('should return eligible for paid payment', async () => {
        mockClient.maybeSingle
          .mockResolvedValueOnce({ data: null, error: null }) // No existing refund
          .mockResolvedValueOnce({
            data: {
              status: PaymentDbStatus.Paid,
              created_at: new Date(Date.now() - 10 * 24 * 60 * 60 * 1000).toISOString(),
            },
            error: null,
          });

        const result = await service.checkEligibility('payment', 'payment-123');

        expect(result.eligible).toBe(true);
        expect(result.reasonCode).toBe('ELIGIBLE');
        expect(result.message).toBe('Payment is eligible for refund');
        expect(result.details?.currentState).toBe(PaymentDbStatus.Paid);
      });

      it('should return not eligible for pending payment', async () => {
        mockClient.maybeSingle
          .mockResolvedValueOnce({ data: null, error: null })
          .mockResolvedValueOnce({
            data: {
              status: PaymentDbStatus.Pending,
              created_at: new Date().toISOString(),
            },
            error: null,
          });

        const result = await service.checkEligibility('payment', 'payment-123');

        expect(result.eligible).toBe(false);
        expect(result.reasonCode).toBe('INVALID_STATE');
        expect(result.message).toContain('must be paid');
      });

      it('should return not eligible for payment not found', async () => {
        mockClient.maybeSingle
          .mockResolvedValueOnce({ data: null, error: null })
          .mockResolvedValueOnce({ data: null, error: null });

        const result = await service.checkEligibility('payment', 'payment-123');

        expect(result.eligible).toBe(false);
        expect(result.reasonCode).toBe('ENTITY_NOT_FOUND');
        expect(result.message).toBe('Payment not found');
      });

      it('should return not eligible if payment is too old', async () => {
        const oldDate = new Date(Date.now() - 100 * 24 * 60 * 60 * 1000);
        mockClient.maybeSingle
          .mockResolvedValueOnce({ data: null, error: null })
          .mockResolvedValueOnce({
            data: {
              status: PaymentDbStatus.Paid,
              created_at: oldDate.toISOString(),
            },
            error: null,
          });

        const result = await service.checkEligibility('payment', 'payment-123');

        expect(result.eligible).toBe(false);
        expect(result.reasonCode).toBe('TOO_OLD');
        expect(result.message).toContain('too old for refund');
        expect(result.details?.ageInDays).toBeGreaterThan(90);
      });

      it('should return not eligible if existing pending refund exists', async () => {
        mockClient.maybeSingle.mockResolvedValueOnce({
          data: { id: 'refund-123', status: 'pending' },
          error: null,
        });

        const result = await service.checkEligibility('payment', 'payment-123');

        expect(result.eligible).toBe(false);
        expect(result.reasonCode).toBe('ALREADY_REFUNDED');
        expect(result.message).toContain('pending refund already exists');
        expect(result.details?.existingRefundId).toBe('refund-123');
      });

      it('should return not eligible if existing approved refund exists', async () => {
        mockClient.maybeSingle.mockResolvedValueOnce({
          data: { id: 'refund-456', status: 'approved' },
          error: null,
        });

        const result = await service.checkEligibility('payment', 'payment-123');

        expect(result.eligible).toBe(false);
        expect(result.reasonCode).toBe('ALREADY_REFUNDED');
        expect(result.message).toContain('approved refund already exists');
        expect(result.details?.existingRefundId).toBe('refund-456');
      });
    });

    describe('Escrow eligibility', () => {
      it('should return eligible for active escrow', async () => {
        mockClient.maybeSingle
          .mockResolvedValueOnce({ data: null, error: null })
          .mockResolvedValueOnce({
            data: {
              status: EscrowDbStatus.Active,
              created_at: new Date(Date.now() - 10 * 24 * 60 * 60 * 1000).toISOString(),
            },
            error: null,
          });

        const result = await service.checkEligibility('escrow', 'escrow-123');

        expect(result.eligible).toBe(true);
        expect(result.reasonCode).toBe('ELIGIBLE');
        expect(result.message).toBe('Escrow is eligible for refund');
      });

      it('should return eligible for claimed escrow', async () => {
        mockClient.maybeSingle
          .mockResolvedValueOnce({ data: null, error: null })
          .mockResolvedValueOnce({
            data: {
              status: EscrowDbStatus.Claimed,
              created_at: new Date(Date.now() - 10 * 24 * 60 * 60 * 1000).toISOString(),
            },
            error: null,
          });

        const result = await service.checkEligibility('escrow', 'escrow-123');

        expect(result.eligible).toBe(true);
        expect(result.reasonCode).toBe('ELIGIBLE');
      });

      it('should return not eligible for expired escrow', async () => {
        mockClient.maybeSingle
          .mockResolvedValueOnce({ data: null, error: null })
          .mockResolvedValueOnce({
            data: {
              status: EscrowDbStatus.Expired,
              created_at: new Date().toISOString(),
            },
            error: null,
          });

        const result = await service.checkEligibility('escrow', 'escrow-123');

        expect(result.eligible).toBe(false);
        expect(result.reasonCode).toBe('INVALID_STATE');
        expect(result.message).toContain('must be active or claimed');
      });

      it('should return not eligible for cancelled escrow', async () => {
        mockClient.maybeSingle
          .mockResolvedValueOnce({ data: null, error: null })
          .mockResolvedValueOnce({
            data: {
              status: EscrowDbStatus.Cancelled,
              created_at: new Date().toISOString(),
            },
            error: null,
          });

        const result = await service.checkEligibility('escrow', 'escrow-123');

        expect(result.eligible).toBe(false);
        expect(result.reasonCode).toBe('INVALID_STATE');
      });
    });

    describe('Link eligibility', () => {
      it('should return eligible for paid link', async () => {
        mockClient.maybeSingle
          .mockResolvedValueOnce({ data: null, error: null })
          .mockResolvedValueOnce({
            data: {
              state: LinkState.PAID,
              created_at: new Date(Date.now() - 10 * 24 * 60 * 60 * 1000).toISOString(),
            },
            error: null,
          });

        const result = await service.checkEligibility('link', 'link-123');

        expect(result.eligible).toBe(true);
        expect(result.reasonCode).toBe('ELIGIBLE');
        expect(result.message).toBe('Link is eligible for refund');
      });

      it('should return not eligible for active link', async () => {
        mockClient.maybeSingle
          .mockResolvedValueOnce({ data: null, error: null })
          .mockResolvedValueOnce({
            data: {
              state: LinkState.ACTIVE,
              created_at: new Date().toISOString(),
            },
            error: null,
          });

        const result = await service.checkEligibility('link', 'link-123');

        expect(result.eligible).toBe(false);
        expect(result.reasonCode).toBe('INVALID_STATE');
        expect(result.message).toContain('must be PAID');
      });

      it('should return not eligible for already refunded link', async () => {
        mockClient.maybeSingle
          .mockResolvedValueOnce({ data: null, error: null })
          .mockResolvedValueOnce({
            data: {
              state: LinkState.REFUNDED,
              created_at: new Date().toISOString(),
            },
            error: null,
          });

        const result = await service.checkEligibility('link', 'link-123');

        expect(result.eligible).toBe(false);
        expect(result.reasonCode).toBe('ALREADY_REFUNDED');
        expect(result.message).toBe('Link has already been refunded');
      });

      it('should return not eligible for draft link', async () => {
        mockClient.maybeSingle
          .mockResolvedValueOnce({ data: null, error: null })
          .mockResolvedValueOnce({
            data: {
              state: LinkState.DRAFT,
              created_at: new Date().toISOString(),
            },
            error: null,
          });

        const result = await service.checkEligibility('link', 'link-123');

        expect(result.eligible).toBe(false);
        expect(result.reasonCode).toBe('INVALID_STATE');
      });
    });

    describe('Reason code stability', () => {
      it('should return consistent reason codes for the same scenarios', async () => {
        // Test 1: Invalid state
        mockClient.maybeSingle
          .mockResolvedValueOnce({ data: null, error: null })
          .mockResolvedValueOnce({
            data: { status: PaymentDbStatus.Pending, created_at: new Date().toISOString() },
            error: null,
          });
        const result1 = await service.checkEligibility('payment', 'p1');
        expect(result1.reasonCode).toBe('INVALID_STATE');

        // Test 2: Too old
        const oldDate = new Date(Date.now() - 100 * 24 * 60 * 60 * 1000);
        mockClient.maybeSingle
          .mockResolvedValueOnce({ data: null, error: null })
          .mockResolvedValueOnce({
            data: { status: PaymentDbStatus.Paid, created_at: oldDate.toISOString() },
            error: null,
          });
        const result2 = await service.checkEligibility('payment', 'p2');
        expect(result2.reasonCode).toBe('TOO_OLD');

        // Test 3: Entity not found
        mockClient.maybeSingle
          .mockResolvedValueOnce({ data: null, error: null })
          .mockResolvedValueOnce({ data: null, error: null });
        const result3 = await service.checkEligibility('payment', 'p3');
        expect(result3.reasonCode).toBe('ENTITY_NOT_FOUND');

        // Test 4: Already refunded
        mockClient.maybeSingle.mockResolvedValueOnce({
          data: { id: 'ref-1', status: 'pending' },
          error: null,
        });
        const result4 = await service.checkEligibility('payment', 'p4');
        expect(result4.reasonCode).toBe('ALREADY_REFUNDED');
      });
    });
  });

  describe('initiateRefund with eligibility check', () => {
    it('should throw ConflictException when eligibility check fails', async () => {
      mockClient.maybeSingle
        .mockResolvedValueOnce({ data: null, error: null }) // idempotency check
        .mockResolvedValueOnce({ data: null, error: null }) // existing refund check
        .mockResolvedValueOnce({
          data: { status: PaymentDbStatus.Pending, created_at: new Date().toISOString() },
          error: null,
        }); // payment check

      await expect(
        service.initiateRefund(
          {
            entityType: 'payment',
            entityId: 'payment-123',
            reasonCode: 'CUSTOMER_REQUEST',
            idempotencyKey: 'key-123',
          },
          'actor-123',
        ),
      ).rejects.toThrow(ConflictException);
    });
  });
});
