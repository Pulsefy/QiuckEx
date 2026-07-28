import { Test, TestingModule } from '@nestjs/testing';
import { DashboardFeedService } from './dashboard-feed.service';
import { DashboardFeedRepository } from './dashboard-feed.repository';
import type { FeedItem } from './dashboard-feed.types';

const mockRepository = {
  getPayments: jest.fn(),
  getRefunds: jest.fn(),
  getWebhookDeliveries: jest.fn(),
  getNotifications: jest.fn(),
  getContractEvents: jest.fn(),
  getUsernameActions: jest.fn(),
};

function makeFeedItem(overrides: Partial<FeedItem> = {}): FeedItem {
  return {
    id: `item_${Math.random().toString(36).slice(2, 8)}`,
    kind: 'payment',
    timestamp: '2026-07-01T10:00:00.000Z',
    title: 'Test Payment',
    description: '100 XLM',
    status: 'success',
    correlationId: 'tx_abc123',
    paymentDetail: null,
    refundDetail: null,
    webhookDetail: null,
    notificationDetail: null,
    contractDetail: null,
    usernameDetail: null,
    ...overrides,
  };
}

describe('DashboardFeedService', () => {
  let service: DashboardFeedService;

  beforeEach(async () => {
    jest.clearAllMocks();

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        DashboardFeedService,
        { provide: DashboardFeedRepository, useValue: mockRepository },
      ],
    }).compile();

    service = module.get(DashboardFeedService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('getFeed', () => {
    it('aggregates items from all sources and returns them sorted by timestamp desc', async () => {
      const address = 'GABC123';

      mockRepository.getPayments.mockResolvedValue([
        makeFeedItem({ id: 'pay_1', kind: 'payment', timestamp: '2026-07-01T10:00:00.000Z' }),
      ]);
      mockRepository.getRefunds.mockResolvedValue([
        makeFeedItem({ id: 'ref_1', kind: 'refund', timestamp: '2026-07-01T11:00:00.000Z' }),
      ]);
      mockRepository.getWebhookDeliveries.mockResolvedValue([
        makeFeedItem({ id: 'whk_1', kind: 'webhook_delivery', timestamp: '2026-07-01T09:00:00.000Z' }),
      ]);
      mockRepository.getNotifications.mockResolvedValue([
        makeFeedItem({ id: 'notif_1', kind: 'notification', timestamp: '2026-07-01T12:00:00.000Z' }),
      ]);
      mockRepository.getContractEvents.mockResolvedValue([
        makeFeedItem({ id: 'ctr_1', kind: 'contract_event', timestamp: '2026-07-01T08:00:00.000Z' }),
      ]);
      mockRepository.getUsernameActions.mockResolvedValue([
        makeFeedItem({ id: 'uname_1', kind: 'username_action', timestamp: '2026-07-01T07:00:00.000Z' }),
      ]);

      const result = await service.getFeed({ address, limit: 100 });

      expect(result.data).toHaveLength(6);
      // Most recent first
      expect(result.data[0].id).toBe('notif_1');
      expect(result.data[1].id).toBe('ref_1');
      expect(result.data[2].id).toBe('pay_1');
      expect(result.data[3].id).toBe('whk_1');
      expect(result.data[4].id).toBe('ctr_1');
      expect(result.data[5].id).toBe('uname_1');

      expect(result.pagination.has_more).toBe(false);
      expect(result.pagination.next_cursor).toBeNull();
      expect(result.isPartial).toBe(false);
    });

    it('returns only the requested kind when kind filter is set', async () => {
      const address = 'GABC123';

      mockRepository.getPayments.mockResolvedValue([
        makeFeedItem({ id: 'pay_1', kind: 'payment', timestamp: '2026-07-01T10:00:00.000Z' }),
      ]);
      mockRepository.getRefunds.mockResolvedValue([]);
      mockRepository.getWebhookDeliveries.mockResolvedValue([]);
      mockRepository.getNotifications.mockResolvedValue([]);
      mockRepository.getContractEvents.mockResolvedValue([]);
      mockRepository.getUsernameActions.mockResolvedValue([]);

      const result = await service.getFeed({ address, kind: 'payment', limit: 100 });

      expect(result.data).toHaveLength(1);
      expect(result.data[0].kind).toBe('payment');
    });

    it('deduplicates items with the same id', async () => {
      const address = 'GABC123';
      const item = makeFeedItem({ id: 'dup_1', kind: 'payment', timestamp: '2026-07-01T10:00:00.000Z' });

      mockRepository.getPayments.mockResolvedValue([item]);
      mockRepository.getRefunds.mockResolvedValue([item]);
      mockRepository.getWebhookDeliveries.mockResolvedValue([]);
      mockRepository.getNotifications.mockResolvedValue([]);
      mockRepository.getContractEvents.mockResolvedValue([]);
      mockRepository.getUsernameActions.mockResolvedValue([]);

      const result = await service.getFeed({ address, limit: 100 });

      expect(result.data).toHaveLength(1);
    });

    it('handles partial failures gracefully', async () => {
      const address = 'GABC123';

      mockRepository.getPayments.mockRejectedValue(new Error('DB down'));
      mockRepository.getRefunds.mockResolvedValue([]);
      mockRepository.getWebhookDeliveries.mockResolvedValue([]);
      mockRepository.getNotifications.mockResolvedValue([]);
      mockRepository.getContractEvents.mockResolvedValue([]);
      mockRepository.getUsernameActions.mockResolvedValue([]);

      const result = await service.getFeed({ address, limit: 100 });

      expect(result.isPartial).toBe(true);
      expect(result.failedSources).toContain('payment');
    });

    it('returns has_more true and correct cursor when data exceeds limit', async () => {
      const address = 'GABC123';
      const items: FeedItem[] = [];
      for (let i = 0; i < 5; i++) {
        items.push(
          makeFeedItem({
            id: `pay_${i}`,
            kind: 'payment',
            timestamp: `2026-07-01T${10 - i}:00:00.000Z`,
          }),
        );
      }

      mockRepository.getPayments.mockResolvedValue(items);
      mockRepository.getRefunds.mockResolvedValue([]);
      mockRepository.getWebhookDeliveries.mockResolvedValue([]);
      mockRepository.getNotifications.mockResolvedValue([]);
      mockRepository.getContractEvents.mockResolvedValue([]);
      mockRepository.getUsernameActions.mockResolvedValue([]);

      const result = await service.getFeed({ address, limit: 3 });

      expect(result.data).toHaveLength(3);
      expect(result.pagination.has_more).toBe(true);
      expect(result.pagination.next_cursor).not.toBeNull();
    });

    it('applies cursor filter to skip already-seen items', async () => {
      const address = 'GABC123';
      const items: FeedItem[] = [];
      for (let i = 0; i < 6; i++) {
        items.push(
          makeFeedItem({
            id: `pay_${i}`,
            kind: 'payment',
            timestamp: `2026-07-01T10:00:00.${String(i).padStart(3, '0')}Z`,
          }),
        );
      }

      mockRepository.getPayments.mockResolvedValue(items);
      mockRepository.getRefunds.mockResolvedValue([]);
      mockRepository.getWebhookDeliveries.mockResolvedValue([]);
      mockRepository.getNotifications.mockResolvedValue([]);
      mockRepository.getContractEvents.mockResolvedValue([]);
      mockRepository.getUsernameActions.mockResolvedValue([]);

      // First page
      const page1 = await service.getFeed({ address, limit: 3 });
      expect(page1.data).toHaveLength(3);
      expect(page1.pagination.next_cursor).not.toBeNull();

      // Second page with cursor
      mockRepository.getPayments.mockResolvedValue(items);
      const page2 = await service.getFeed({
        address,
        limit: 3,
        cursor: page1.pagination.next_cursor!,
      });

      expect(page2.data).toHaveLength(3);
      // No overlap between pages
      const page1Ids = page1.data.map((i) => i.id);
      const page2Ids = page2.data.map((i) => i.id);
      expect(page1Ids.some((id) => page2Ids.includes(id))).toBe(false);
    });

    it('uses deterministic tiebreaking for same-timestamp items', async () => {
      const address = 'GABC123';
      const ts = '2026-07-01T10:00:00.000Z';
      const items = [
        makeFeedItem({ id: 'pay_alpha', kind: 'payment', timestamp: ts }),
        makeFeedItem({ id: 'pay_charlie', kind: 'payment', timestamp: ts }),
        makeFeedItem({ id: 'pay_bravo', kind: 'payment', timestamp: ts }),
      ];

      mockRepository.getPayments.mockResolvedValue(items);
      mockRepository.getRefunds.mockResolvedValue([]);
      mockRepository.getWebhookDeliveries.mockResolvedValue([]);
      mockRepository.getNotifications.mockResolvedValue([]);
      mockRepository.getContractEvents.mockResolvedValue([]);
      mockRepository.getUsernameActions.mockResolvedValue([]);

      const result = await service.getFeed({ address, limit: 100 });

      // Sorted by id DESC (tiebreaker)
      expect(result.data[0].id).toBe('pay_charlie');
      expect(result.data[1].id).toBe('pay_bravo');
      expect(result.data[2].id).toBe('pay_alpha');
    });
  });
});
