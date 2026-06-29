import { Test } from '@nestjs/testing';
import { PaymentLinkExpiryService } from '../payment-link-expiry.service';
import { SupabaseService } from '../../supabase/supabase.service';
import { EventEmitter2 } from '@nestjs/event-emitter';
import { AuditService } from '../../audit/audit.service';

describe('PaymentLinkExpiryService', () => {
  let svc: PaymentLinkExpiryService;
  let mockSupabase: any;
  let mockAudit: any;
  let events: EventEmitter2;

  beforeEach(async () => {
    mockSupabase = {
      getClient: jest.fn(),
    };

    // Minimal chainable builder used by service
    const builder = {
      update: jest.fn().mockReturnThis(),
      eq: jest.fn().mockReturnThis(),
      not: jest.fn().mockReturnThis(),
      lte: jest.fn().mockReturnThis(),
      select: jest.fn().mockResolvedValue({ data: [], error: null }),
      from: jest.fn().mockReturnThis(),
      insert: jest.fn().mockResolvedValue({ data: [], error: null }),
    };

    mockSupabase.getClient.mockReturnValue(builder);

    mockAudit = { log: jest.fn().mockResolvedValue(undefined) };

    events = new EventEmitter2();

    const module = await Test.createTestingModule({
      providers: [
        PaymentLinkExpiryService,
        { provide: SupabaseService, useValue: mockSupabase },
        { provide: EventEmitter2, useValue: events },
        { provide: AuditService, useValue: mockAudit },
      ],
    }).compile();

    svc = module.get(PaymentLinkExpiryService);
  });

  it('marks expired links and writes audit + emits event', async () => {
    const updatedRow = {
      id: '1111-2222',
      owner_public_key: 'GABCDEFG',
      destination_public_key: 'GDEST',
      expires_at: new Date().toISOString(),
    };

    const client = mockSupabase.getClient();
    client.select.mockResolvedValue({ data: [updatedRow], error: null });
    client.insert.mockResolvedValue({ data: [{ id: 'audit1' }], error: null });

    const spyEmit = jest.spyOn(events, 'emit');

    const count = await svc.runExpirySweep('run-1');
    expect(count).toBe(1);
    expect(mockAudit.log).toHaveBeenCalledWith('system:expiry-worker', 'payment_link.expired', String(updatedRow.id), expect.any(Object));
    expect(spyEmit).toHaveBeenCalledWith('payment.link.expired', expect.objectContaining({ linkId: String(updatedRow.id) }));
  });

  it('is idempotent when there are no open expired links', async () => {
    const client = mockSupabase.getClient();
    client.select.mockResolvedValue({ data: [], error: null });

    const count = await svc.runExpirySweep('run-2');
    expect(count).toBe(0);
    expect(mockAudit.log).not.toHaveBeenCalled();
  });
});
