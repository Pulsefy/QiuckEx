import { Test } from '@nestjs/testing';
import { PaymentLinkExpiryService } from '../payment-link-expiry.service';
import { PAYMENT_LINKS_REPOSITORY } from '../payment-links.repository';
import { EventEmitter2 } from '@nestjs/event-emitter';
import { AuditService } from '../../audit/audit.service';

describe('PaymentLinkExpiryService', () => {
  let svc: PaymentLinkExpiryService;
  let mockRepo: {
    markExpiredLinks: jest.Mock;
    insertExpiryAudit: jest.Mock;
  };
  let mockAudit: { log: jest.Mock };
  let events: EventEmitter2;

  beforeEach(async () => {
    mockRepo = {
      markExpiredLinks: jest.fn().mockResolvedValue([]),
      insertExpiryAudit: jest.fn().mockResolvedValue(undefined),
    };

    mockAudit = { log: jest.fn().mockResolvedValue(undefined) };

    events = new EventEmitter2();

    const module = await Test.createTestingModule({
      providers: [
        PaymentLinkExpiryService,
        { provide: PAYMENT_LINKS_REPOSITORY, useValue: mockRepo },
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

    mockRepo.markExpiredLinks.mockResolvedValue([updatedRow]);

    const spyEmit = jest.spyOn(events, 'emit');

    const count = await svc.runExpirySweep('run-1');
    expect(count).toBe(1);
    expect(mockAudit.log).toHaveBeenCalledWith('system:expiry-worker', 'payment_link.expired', String(updatedRow.id), expect.any(Object));
    expect(mockRepo.insertExpiryAudit).toHaveBeenCalledWith(
      expect.objectContaining({ linkId: String(updatedRow.id), runId: 'run-1' }),
    );
    expect(spyEmit).toHaveBeenCalledWith('payment.link.expired', expect.objectContaining({ linkId: String(updatedRow.id) }));
  });

  it('is idempotent when there are no open expired links', async () => {
    mockRepo.markExpiredLinks.mockResolvedValue([]);

    const count = await svc.runExpirySweep('run-2');
    expect(count).toBe(0);
    expect(mockAudit.log).not.toHaveBeenCalled();
    expect(mockRepo.insertExpiryAudit).not.toHaveBeenCalled();
  });
});
