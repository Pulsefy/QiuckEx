import {
  Injectable,
  NotFoundException,
  Logger,
} from '@nestjs/common';
import * as crypto from 'crypto';
import * as bcrypt from 'bcrypt';
import { ApiKeysRepository } from './api-keys.repository';
import { CreateApiKeyDto } from './dto/create-api-key.dto';
import {
  ApiKeyCreated,
  ApiKeyPublic,
  ApiKeyRecord,
  ApiKeyScope,
} from './api-keys.types';
import { decodeCursor, clampLimit } from '../common/pagination/cursor.util';
import { PaginationMetaDto } from '../dto/pagination/pagination.dto';

const BCRYPT_ROUNDS = 10;
const DEFAULT_QUOTA = 10_000;
const KEY_PREFIX_LENGTH = 8; // chars used for prefix display / lookup

@Injectable()
export class ApiKeysService {
  private readonly logger = new Logger(ApiKeysService.name);

  constructor(private readonly repo: ApiKeysRepository) {}

  // ---------------------------------------------------------------------------
  // Public API
  // ---------------------------------------------------------------------------

  async create(dto: CreateApiKeyDto): Promise<ApiKeyCreated> {
    const rawKey = this.generateRawKey();
    const prefix = rawKey.slice(0, KEY_PREFIX_LENGTH + 3); // "qx_" + 8 chars
    const hash = await bcrypt.hash(rawKey, BCRYPT_ROUNDS);

    const record = await this.repo.insert({
      name: dto.name,
      key_hash: hash,
      key_prefix: prefix,
      scopes: dto.scopes,
      owner_id: dto.owner_id ?? null,
      monthly_quota: DEFAULT_QUOTA,
    });

    this.logger.log(`API key created: id=${record.id} name="${record.name}"`);

    return { ...this.toPublic(record), key: rawKey };
  }

  async list(owner_id?: string): Promise<ApiKeyPublic[]> {
    const records = await this.repo.findAll(owner_id);
    return records.map((r) => this.toPublic(r));
  }

  async listPaginated(
    owner_id: string | undefined,
    cursor?: string,
    limit?: number,
  ): Promise<{ data: ApiKeyPublic[]; pagination: PaginationMetaDto }> {
    const decodedCursor = cursor ? decodeCursor(cursor) : null;
    const effectiveLimit = clampLimit(limit);
    const result = await this.repo.findAllPaginated(owner_id, decodedCursor, effectiveLimit);
    return {
      data: result.data.map((r) => this.toPublic(r)),
      pagination: {
        next_cursor: result.next_cursor,
        has_more: result.has_more,
        limit: result.limit,
      },
    };
  }

  async revoke(id: string): Promise<void> {
    const record = await this.repo.findById(id);
    if (!record) throw new NotFoundException('API key not found');

    await this.repo.revoke(id);
    this.logger.log(`API key revoked: id=${id}`);
  }

  async rotate(id: string): Promise<ApiKeyCreated> {
    const record = await this.repo.findById(id);
    if (!record) throw new NotFoundException('API key not found');

    const rawKey = this.generateRawKey();
    const prefix = rawKey.slice(0, KEY_PREFIX_LENGTH + 3);
    const hash = await bcrypt.hash(rawKey, BCRYPT_ROUNDS);

    const updated = await this.repo.updateKey(id, {
      key_hash: hash,
      key_prefix: prefix,
    });

    this.logger.log(`API key rotated: id=${id}`);

    return { ...this.toPublic(updated), key: rawKey };
  }

  async getUsage(owner_id?: string) {
    return this.repo.getUsageSummary(owner_id);
  }

  // ---------------------------------------------------------------------------
  // Guard-facing: validate an incoming raw key and return its record
  // ---------------------------------------------------------------------------

  async validateKey(
    rawKey: string,
  ): Promise<{ record: ApiKeyRecord; hasScope: (s: ApiKeyScope) => boolean } | null> {
    const prefix = rawKey.slice(0, KEY_PREFIX_LENGTH + 3);
    const candidates = await this.repo.findByPrefix(prefix);

    for (const record of candidates) {
      const isCurrentMatch = await bcrypt.compare(rawKey, record.key_hash);
      let isOldMatch = false;

      if (!isCurrentMatch && record.key_hash_old && record.rotated_at) {
        const rotatedAt = new Date(record.rotated_at).getTime();
        const now = Date.now();
        const overlapMs = 24 * 60 * 60 * 1000; // 24 hours

        if (now - rotatedAt < overlapMs) {
          isOldMatch = await bcrypt.compare(rawKey, record.key_hash_old);
        }
      }

      if (isCurrentMatch || isOldMatch) {
        // Fire-and-forget usage increment — don't block the request
        this.repo
          .incrementUsage(record.id)
          .catch((err) =>
            this.logger.warn(`Failed to increment usage for ${record.id}: ${err}`),
          );

        return {
          record,
          hasScope: (scope: ApiKeyScope) => record.scopes.includes(scope),
        };
      }
    }

    return null;
  }

  // ---------------------------------------------------------------------------
  // Quota check
  // ---------------------------------------------------------------------------

  isOverQuota(record: ApiKeyRecord): boolean {
    const now = new Date();
    const lastReset = new Date(record.last_reset_at);

    // If we've moved into a new month, the quota hasn't been reset in the DB yet
    // (it happens on the next increment), but for the guard's sake, it's NOT over quota.
    if (
      now.getUTCFullYear() > lastReset.getUTCFullYear() ||
      now.getUTCMonth() > lastReset.getUTCMonth()
    ) {
      return false;
    }

    return record.request_count >= record.monthly_quota;
  }

  // ---------------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------------

  private generateRawKey(): string {
    const bytes = crypto.randomBytes(24).toString('hex');
    return `qx_live_${bytes}`;
  }

  private toPublic(record: ApiKeyRecord): ApiKeyPublic {
    return {
      id: record.id,
      name: record.name,
      key_prefix: record.key_prefix,
      scopes: record.scopes,
      is_active: record.is_active,
      request_count: record.request_count,
      monthly_quota: record.monthly_quota,
      last_used_at: record.last_used_at,
      created_at: record.created_at,
    };
  }
}
