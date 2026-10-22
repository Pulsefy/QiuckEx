import { ReceiptsService } from './receipts.service';
import { ReceiptRepository, ReceiptRecord } from './receipts.repository';

class InMemoryReceiptRepository implements ReceiptRepository {
  private readonly store = new Map<string, ReceiptRecord>();

  async findById(id: string): Promise<ReceiptRecord | null> {
    return this.store.get(id) ?? null;
  }

  async findByTxHash(txHash: string): Promise<ReceiptRecord | null> {
    for (const record of this.store.values()) {
      if (record.txHash === txHash) {
        return record;
      }
    }
    return null;
  }

  async upsert(input: {
    id: string;
    txHash: string;
    normalized: Record<string, unknown>;
    hash: string;
  }): Promise<ReceiptRecord> {
    const existing = this.store.get(input.id);
    const now = new Date().toISOString();
    const record: ReceiptRecord = {
      id: input.id,
      txHash: input.txHash,
      normalized: input.normalized,
      hash: input.hash,
      createdAt: existing?.createdAt ?? now,
      updatedAt: now,
    };
    this.store.set(record.id, record);
    return record;
  }

  async delete(id: string): Promise<void> {
    this.store.delete(id);
  }
}

describe('ReceiptsService', () => {
  let repository: InMemoryReceiptRepository;
  let service: ReceiptsService;

  const sampleInput = {
    txHash: 'abcdef123456',
    amount: '100.0000000',
    asset: 'XEL',
    from: 'GFAB1',
    to: 'GBBB2',
    timestamp: '2024-01-01T00:00:00Z',
  };

  beforeEach(() => {
    repository = new InMemoryReceiptRepository();
    service = new ReceiptsService(repository);
  });

  it('normalizes and hashes receipts consistently', async () => {
    const a = await service.createReceipt(sampleInput);
    const b = await service.createReceipt({ ...sampleInput });

    expect(a.hash).toBe(b.hash);
    expect(a.normalized).toEqual(b.normalized);
  });

  it('persists receipts through the repository', async () => {
    const created = await service.createReceipt(sampleInput);
    const stored = await repository.findById(created.id);

    expect(stored).not.toBeNull();
    expect(stored!.hash).toEqual(created.hash);
  });

  it('returns not-found for missing receipts', async () => {
    await expect(service.getReceipt('mock-missing-id')).rejects.toThrow();
  });

  it('shares state across instances via the repository', async () => {
    const otherService = new ReceiptsService(repository);
    const created = await service.createReceipt(sampleInput);
    const fetched = await otherService.getReceipt(created.id);

    expect(fetched.id).toEqual(created.id);
    expect(fetched.hash).toEqual(created.hash);
  });

  it('survives a service restart with the same repository', async () => {
    const created = await service.createReceipt(sampleInput);
    const restarted = new ReceiptsService(repository);
    const fetched = await restarted.getReceipt(created.id);

    expect(fetched).toMatchObject({ id: created.id, hash: created.hash });
  });
});
