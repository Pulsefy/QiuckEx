import { ContractChangeWebhookService } from './contract-change-webhook.service';
import { SupabaseService } from '../supabase/supabase.service';

describe('ContractChangeWebhookService', () => {
  const store: Array<{ id: string } & Record<string, unknown>> = [];

  const createChain = () => {
    const chain = {
      select: jest.fn().mockReturnThis(),
      eq: jest.fn().mockReturnThis(),
      upsert: jest.fn().mockImplementation((row: unknown) => {
        const rowData = row as { id: string };
        const existingIndex = store.findIndex((r) => r.id === rowData.id);
        if (existingIndex >= 0) {
          store[existingIndex] = { ...store[existingIndex], ...rowData };
        } else {
          store.push(rowData as { id: string } & Record<string, unknown>);
        }
        return Promise.resolve({ data: null, error: null });
      }),
      delete: jest.fn().mockImplementation(() => {
        return chain;
      }),
      order: jest.fn().mockImplementation(() => {
        return Promise.resolve({ data: [...store], error: null });
      }),
      // Handle the case where eq is the last call in the chain
      then: (resolve: (value: unknown) => void) => resolve({ data: [...store], error: null }),
    };
    
    // For delete().eq()
    chain.eq = jest.fn().mockImplementation((key: string, value: unknown) => {
      if (key === 'id') {
        const index = store.findIndex(r => r.id === value);
        if (index >= 0) store.splice(index, 1);
      }
      return Promise.resolve({ data: null, error: null });
    });

    return chain;
  };

  const mockClient = {
    from: jest.fn(() => createChain()),
  };

  const mockSupabaseService = {
    getClient: jest.fn(() => mockClient as never),
  };

  const createFailingSupabaseService = () => ({
    getClient: jest.fn(() => ({
      from: jest.fn(() => ({
        upsert: jest.fn().mockResolvedValue({ error: new Error('DB error') }),
        select: jest.fn().mockReturnThis(),
        eq: jest.fn().mockResolvedValue({ error: new Error('DB error') }),
        delete: jest.fn().mockReturnThis(),
        order: jest.fn().mockResolvedValue({ error: new Error('DB error') }),
      })),
    })),
  });

  let service: ContractChangeWebhookService;

  beforeEach(() => {
    store.length = 0;
    jest.clearAllMocks();
    service = new ContractChangeWebhookService(
      mockSupabaseService as unknown as SupabaseService,
    );
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
    const failingService = new ContractChangeWebhookService(
      createFailingSupabaseService() as unknown as SupabaseService
    );
    
    const webhook = await failingService.registerWebhook('https://delete-me.example.com/webhook');
    const deleted = await failingService.deleteWebhook(webhook.id);
    expect(deleted).toBe(true);
  });

  it('returns false for a missing id', async () => {
    const deleted = await service.deleteWebhook('does-not-exist');
    expect(deleted).toBe(false);
  });

  it('filters to only enabled webhooks', async () => {
    const failingService = new ContractChangeWebhookService(
      createFailingSupabaseService() as unknown as SupabaseService
    );
    
    const webhook = await failingService.registerWebhook('https://enabled.example.com/webhook');
    const webhooks = await failingService.getEnabledWebhooks();
    const found = webhooks.find((w) => w.id === webhook.id);
    expect(found?.enabled).toBe(true);
  });
});
