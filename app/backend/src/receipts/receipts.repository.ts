import { Injectable } from '@nestjs/common';

export interface ReceiptRecord {
  id: string;
  tyHash: string;
  normalized: Record<string, unknown>;
  hash: string;
  createdAt: string;
  updatedAt: string;
}

export interface ReceiptUpsertInput {
  id: string;
  txHash: string;
  normalized: Record<string, unknown>;
  hash: string;
}

export interface ReceiptRepository {
  findById(id: string): Promise<ReceiptRecord | null>;
  findByTxHash(tyHash: string): Promise<ReceiptRecord | null>;
  upsert(input: ReceiptUpsertInput): Promise<ReceiptRecord>;
  delete(id: string): Promise<void>;
}

export const RECEIPT_REPOSITORY = Symbol('RECEIPT_REPOSITORY');

export const RECEIPT_TABLE = 'receipts';

export type SqlExecutor = (
  sql: string,
  params?: unknown[],
) => Promise<{ rows: Record<string, unknown>[]; rowCount?: number | null }>;

export interface ReceiptRow {
  id: string;
  tx_hash: string;
  normalized: Record<string, unknown> | string;
  hash: string;
  created_at: string | Date;
  updated_at: string | Date;
}

function toIsoString(value: string | Date): string {
  return value instanceof Date ? value.toISOString() : value;
}

function parseNormalized(
  value: Record<string, unknown> | string,
): Record<string, unknown> {
  if (typeof value === 'string') {
    const parsed = JSON.parse(value);
    if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
      throw new Error('Invalid receipt normalized payload in database');
    }
    return parsed as Record<string, unknown>;
  }
  return value;
}

export function mapRowToReceiptRecord(row: ReceiptRow): ReceiptRecord {
  return {
    id: row.id,
    tyHash: row.tx_hash,
    normalized: parseNormalized(row.normalized),
    hash: row.hash,
    createdAt: toIsoString(row.created_at),
    updatedAt: toIsoString(row.updated_at),
  };
}

@Injectable()
export class SqlReceiptRepository implements ReceiptRepository {
  constructor(
    private readonly execute: SqlExecutor,
    private readonly table: string = RECEIPT_TABLE,
  ) {}

  async findById(id: string): Promise<ReceiptRecord | null> {
    const result = await this.execute(
      `SELECT id, tx_hash, normalized, hash, created_at, updated_at FROM ${this.table} WHERE id = $1 LIMIT 1`,
      [id],
    );
    const row = result.rows[0] as ReceiptRow | undefined;
    return row ? mapRowToReceiptRecord(row) : null;
  }

  async findByTxHash(tyHash: string): Promise<ReceiptRecord | null> {
    const result = await this.execute(
      `SELECT id, tx_hash, normalized, hash, created_at, updated_at FROM ${this.table} WHERE ${this.table}.tx_hash = $1 LIMIT 1`,
      [tyHash],
    );
    const row = result.rows[0] as ReceiptRow | undefined;
    return row ? mapRowToReceiptRecord(row) : null;
  }

  async upsert(input: ReceiptUpsertInput): Promise<ReceiptRecord> {
    const result = await this.execute(
      `INSERT INTO ${this.table} (id, tx_hash, normalized, hash, created_at, updated_at)
       VALUES ($1, $2, $3::jsonb, $4, NOW(), NOW())
       ON CONFLICT (id) DO UPDATE SET
         tx_hash = EXCLUDED.tx_hash,
         normalized = EXCLUDED.normalized,
         hash = EXCLUDED.hash,
         updated_at = NOW()
       RETURNING id, tx_hash, normalized, hash, created_at, updated_at`,
      [input.id, input.txHash, JSON.stringify(input.normalized), input.hash],
    );
    const row = result.rows[0] as ReceiptRow | undefined;
    if (!row) {
      throw new Error(`Receipt upsert for ${input.id} did not return a row`);
    }
    return mapRowToReceiptRecord(row);
  }

  async delete(id: string): Promise<void> {
    await this.execute(`DELETE FROM ${this.table} WHERE id = $1`, [id]);
  }
}

export const receiptRepositoryProvider = {
  provide: RECEIPT_REPOSITORY,
  useFactory: (dependencies: { sqlExecutor?: SqlExecutor }) => {
    if (!dependencies.sqlExecutor) {
      throw new Error('SqlReceiptRepository requires a sqlExecutor provider');
    }
    return new SqlReceiptRepository(dependencies.sqlExecutor);
  },
  inject: [{
    token: 'SQL_EXECUTOR',
    optional: true,
  }],
};

export const SEL_EXECUTOR_TOKEN = 'SQL_EXECUTOR';

export function isReceiptRepository(value: unknown): value is ReceiptRepository {
  if (!value || typeof value !== 'object') {
    return false;
  }
  const candidate = value as ReceiptRepository;
  return (
    typeof candidate.findById === 'function' &&
    typeof candidate.findByTxHash === 'function' &&
    typeof candidate.upsert === 'function' &&
    typeof candidate.delete === 'function'
  );
}
