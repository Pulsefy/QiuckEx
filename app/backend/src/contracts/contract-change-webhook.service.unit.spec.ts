import { ContractChangeWebhookService } from './contract-change-webhook.service';

describe('ContractChangeWebhookService', () => {
  const store: Record<string, unknown>[] = [];

  const createChain = () => {
    const chain: Record<string, jest.Mock> = {
      select: jest.fn().mockReturnThis(),
      eq: jest.fn().mockReturnThis(),
      upsert: jest.fn().mockImplementation((row: unknown) => {
        const existing = store.find((r) => r.id === (row as { id: string }).id);
        if (existing) {
          Object.assign(existing, row);
        } else {
          store.push(row as typeof store[number]);
        }
        return chain;
      }),
      delete: jest.fn().mockReturnThis(),
      order: jest.fn().mockImplementation(() => {
        return Promise.resolve({ data: [...store], error: null });
      }),
    };
    return chain;
  };

  const mockClient = {
    from: jest.fn(() => createChain()),
  };

  const mockSupabaseService = {
    getClient: jest.fn(() => mockClient as never),
  };

  const service = new ContractChangeWebhookService(
    mockSupabaseService as unknown as never,
  );

  beforeEach(() => {
    store.length = 0;
    jest.clearAllMocks();
  });

  it('registers a webhook with a generated secret', async () => {
    const webhook = await service.registerWebhook('https://example.com/webhook');
    expect(webhook.webhookUrl).toBe('https://example.com/webhook');
    expect(webhook.secret).toMatch(/^cwhsec_/);
    expect(webhook.id).toBeDefined();
    expect(webhook.enabled).toBe(true);
  });

  it('registers a webhook with a custom secret', async () => {
    const webhook = await service.registerWebhook(
      'https://example.com/webhook',
      'custom-secret',
    );
    expect(webhook.secret).toBe('custom-secret');
  });

  it('returns registered webhooks', async () => {
    await service.registerWebhook('https://first.example.com/webhook');
    await service.registerWebhook('https://second.example.com/webhook');

    const webhooks = await service.listWebhooks();
    expect(webhooks.length).toBeGreaterThanOrEqual(2);
  });

  it('removes a webhook by id', async () => {
    const webhook = await service.registerWebhook('https://delete-me.example.com/webhook');
    const deleted = await service.deleteWebhook(webhook.id);
    expect(deleted).toBe(true);
  });

  it('returns false for a missing id', async () => {
    const deleted = await service.deleteWebhook('does-not-exist');
    expect(deleted).toBe(false);
  });

  it('filters to only enabled webhooks', async () => {
    const webhook = await service.registerWebhook('https://enabled.example.com/webhook');
    const webhooks = await service.getEnabledWebhooks();
    const found = webhooks.find((w) => w.id === webhook.id);
    expect(found?.enabled).toBe(true);
  });
});
