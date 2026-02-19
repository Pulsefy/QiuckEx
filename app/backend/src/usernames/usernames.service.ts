import { Injectable } from '@nestjs/common';
import { SupabaseService } from '../supabase/supabase.service';
import { AppConfigService } from '../config';
import {
  USERNAME_MIN_LENGTH,
  USERNAME_MAX_LENGTH,
  USERNAME_PATTERN,
} from './constants';
import {
  UsernameConflictError,
  UsernameLimitExceededError,
  UsernameValidationError,
  UsernameErrorCode,
} from './errors';

const TABLE = 'usernames';
const PG_UNIQUE_VIOLATION = '23505';

export interface UsernameRow {
  id: string;
  username: string;
  public_key: string;
  created_at: string;
}

@Injectable()
export class UsernamesService {
  constructor(
    private readonly supabase: SupabaseService,
    private readonly config: AppConfigService,
  ) {}

  /**
   * Normalize username for storage (lowercase). Validation (length, pattern) is done by DTO.
   */
  normalizeUsername(username: string): string {
    return username.trim().toLowerCase();
  }

  /**
   * Validate format server-side (length and pattern). DTO already validates; this is a safeguard.
   */
  validateFormat(username: string): void {
    const normalized = this.normalizeUsername(username);
    if (normalized.length < USERNAME_MIN_LENGTH || normalized.length > USERNAME_MAX_LENGTH) {
      throw new UsernameValidationError(
        UsernameErrorCode.INVALID_FORMAT,
        `Username must be between ${USERNAME_MIN_LENGTH} and ${USERNAME_MAX_LENGTH} characters`,
        'username',
      );
    }
    if (!USERNAME_PATTERN.test(normalized)) {
      throw new UsernameValidationError(
        UsernameErrorCode.INVALID_FORMAT,
        `Username must contain only lowercase letters, numbers, and underscores`,
        'username',
      );
    }
  }

  /**
   * Create a username. Enforces uniqueness (with race-condition safety via DB constraint)
   * and optional per-wallet limit.
   */
  async create(username: string, publicKey: string): Promise<{ ok: true }> {
    const normalized = this.normalizeUsername(username);
    this.validateFormat(username);

    const maxPerWallet = this.config.maxUsernamesPerWallet;
    if (typeof maxPerWallet === 'number' && maxPerWallet > 0) {
      const count = await this.countByPublicKey(publicKey);
      if (count >= maxPerWallet) {
        throw new UsernameLimitExceededError(publicKey, maxPerWallet);
      }
    }

    const client = this.supabase.getClient();
    const { error } = await client.from(TABLE).insert({
      username: normalized,
      public_key: publicKey,
    });

    if (error) {
      if (error.code === PG_UNIQUE_VIOLATION) {
        throw new UsernameConflictError(normalized);
      }
      throw error;
    }

    return { ok: true };
  }

  /**
   * Count usernames registered for a wallet (for limit enforcement).
   */
  async countByPublicKey(publicKey: string): Promise<number> {
    const client = this.supabase.getClient();
    const { count, error } = await client
      .from(TABLE)
      .select('*', { count: 'exact', head: true })
      .eq('public_key', publicKey);

    if (error) throw error;
    return count ?? 0;
  }

  /**
   * List usernames for a wallet.
   */
  async listByPublicKey(publicKey: string): Promise<UsernameRow[]> {
    const client = this.supabase.getClient();
    const { data, error } = await client
      .from(TABLE)
      .select('id, username, public_key, created_at')
      .eq('public_key', publicKey)
      .order('created_at', { ascending: true });

    if (error) throw error;
    return (data as UsernameRow[]) ?? [];
  }
}
