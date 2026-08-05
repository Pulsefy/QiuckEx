import {
  ForbiddenException,
  Injectable,
  Logger,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { SupabaseService } from '../supabase/supabase.service';
import {
  DEMO_LINKS,
  DEMO_TRANSACTIONS,
  type DemoLink,
  type DemoTransaction,
} from './demo.fixtures';

export interface DemoSeedResult {
  seededLinks: number;
  seededTransactions: number;
  skippedLinks: number;
  skippedTransactions: number;
}

export interface DemoClearResult {
  deletedLinks: number;
  deletedTransactions: number;
}

export interface DemoCountResult {
  links: number;
  transactions: number;
}

@Injectable()
export class DemoService {
  private readonly logger = new Logger(DemoService.name);

  constructor(
    private readonly configService: ConfigService,
    private readonly supabaseService: SupabaseService,
  ) {}

  /**
   * Throws {@link ForbiddenException} unless the active Stellar network is
   * `"testnet"`.  Called at the top of every public method.
   */
  private assertTestnet(): void {
    const network = this.configService.get<{ network: string }>('stellar')?.network
      ?? process.env['NETWORK']
      ?? process.env['STELLAR_NETWORK']
      ?? 'testnet';

    if (network !== 'testnet') {
      throw new ForbiddenException({
        error: 'DEMO_MODE_UNAVAILABLE',
        message: 'Demo mode is only available on testnet.',
      });
    }
  }

  /**
   * Upserts all demo fixtures into the database.
   * Idempotent — safe to call multiple times; existing demo rows are
   * overwritten with the same values so state stays deterministic.
   */
  async seed(): Promise<DemoSeedResult> {
    this.assertTestnet();

    const [linkResult, txResult] = await Promise.all([
      this.seedLinks(),
      this.seedTransactions(),
    ]);

    this.logger.log(
      `Demo seed complete: ${linkResult.seeded} links, ${txResult.seeded} transactions`,
    );

    return {
      seededLinks:        linkResult.seeded,
      seededTransactions: txResult.seeded,
      skippedLinks:       linkResult.skipped,
      skippedTransactions: txResult.skipped,
    };
  }

  /**
   * Removes all rows whose `id` matches a known demo fixture ID.
   * Does not touch any non-demo data.
   */
  async clear(): Promise<DemoClearResult> {
    this.assertTestnet();

    const linkIds = DEMO_LINKS.map((l) => l.id);
    const txIds   = DEMO_TRANSACTIONS.map((t) => t.id);

    const client = this.supabaseService.getClient();

    const [linkDel, txDel] = await Promise.all([
      client.from('links').delete().in('id', linkIds).select('id'),
      client.from('transactions').delete().in('id', txIds).select('id'),
    ]);

    const deletedLinks        = (linkDel.data ?? []).length;
    const deletedTransactions = (txDel.data ?? []).length;

    this.logger.log(
      `Demo clear complete: ${deletedLinks} links, ${deletedTransactions} transactions removed`,
    );

    return { deletedLinks, deletedTransactions };
  }

  /**
   * Returns which demo fixtures are currently present in the database.
   * Useful for the controller to report partial-seed state.
   */
  async status(): Promise<{
    network: string;
    seededLinks: string[];
    seededTransactions: string[];
  }> {
    this.assertTestnet();

    const linkIds = DEMO_LINKS.map((l) => l.id);
    const txIds   = DEMO_TRANSACTIONS.map((t) => t.id);
    const client  = this.supabaseService.getClient();

    const [linkRows, txRows] = await Promise.all([
      client.from('links').select('id').in('id', linkIds),
      client.from('transactions').select('id').in('id', txIds),
    ]);

    return {
      network:            'testnet',
      seededLinks:        (linkRows.data ?? []).map((r: { id: string }) => r.id),
      seededTransactions: (txRows.data ?? []).map((r: { id: string }) => r.id),
    };
  }

  /**
   * Checks if any demo data exists in the database.
   * Returns true if at least one demo link or transaction is present.
   */
  async exists(): Promise<boolean> {
    this.assertTestnet();

    const status = await this.status();
    return status.seededLinks.length > 0 || status.seededTransactions.length > 0;
  }

  /**
   * Gets the count of demo records currently in the database.
   * Returns the number of demo links and transactions.
   */
  async count(): Promise<DemoCountResult> {
    this.assertTestnet();

    const linkIds = DEMO_LINKS.map((l) => l.id);
    const txIds   = DEMO_TRANSACTIONS.map((t) => t.id);
    const client  = this.supabaseService.getClient();

    const [linkRows, txRows] = await Promise.all([
      client.from('links').select('id', { count: 'exact', head: true }).in('id', linkIds),
      client.from('transactions').select('id', { count: 'exact', head: true }).in('id', txIds),
    ]);

    return {
      links:        linkRows.count || 0,
      transactions: txRows.count || 0,
    };
  }

  /**
   * Gets the timestamp of the last successful seed reset.
   * Returns null if no reset has been performed or timestamp is not stored.
   */
  async getLastResetTime(): Promise<Date | null> {
    try {
      const client = this.supabaseService.getClient();
      const { data, error } = await client
        .from('seed_reset_settings')
        .select('last_reset_time')
        .limit(1)
        .single();

      if (error) {
        // Table might not exist yet or no settings found
        this.logger.debug('No seed reset settings found');
        return null;
      }

      if (data && data.last_reset_time) {
        return new Date(data.last_reset_time);
      }

      return null;
    } catch (error) {
      this.logger.debug(
        `Failed to get last reset time: ${(error as Error).message}`,
      );
      return null;
    }
  }

  /**
   * Sets the timestamp of the last successful seed reset.
   * Updates or inserts the value in the seed_reset_settings table.
   */
  async setLastResetTime(timestamp: Date): Promise<void> {
    try {
      const client = this.supabaseService.getClient();
      
      // Check if settings exist
      const { data: existing } = await client
        .from('seed_reset_settings')
        .select('id')
        .limit(1)
        .single();

      if (existing) {
        // Update existing settings
        const { error } = await client
          .from('seed_reset_settings')
          .update({ 
            last_reset_time: timestamp.toISOString(),
            updated_at: new Date().toISOString(),
          })
          .eq('id', existing.id);

        if (error) {
          this.logger.warn(`Failed to update last reset time: ${error.message}`);
        } else {
          this.logger.debug(`Last reset time updated to ${timestamp.toISOString()}`);
        }
      } else {
        // Insert new settings
        const { error } = await client
          .from('seed_reset_settings')
          .insert({
            enabled: true,
            interval: '0 0 * * *',
            exclusions: [],
            max_retries: 3,
            retry_on_failure: true,
            last_reset_time: timestamp.toISOString(),
            total_resets: 0,
            successful_resets: 0,
            failed_resets: 0,
          });

        if (error) {
          this.logger.warn(`Failed to insert last reset time: ${error.message}`);
        } else {
          this.logger.debug(`Last reset time set to ${timestamp.toISOString()}`);
        }
      }
    } catch (error) {
      // Non-critical operation - log but don't throw
      this.logger.warn(
        `Failed to set last reset time: ${(error as Error).message}`,
      );
    }
  }

  /**
   * Increments the reset counters in the settings table.
   * Used to track total, successful, and failed resets.
   */
  async incrementResetCounters(
    success: boolean,
  ): Promise<void> {
    try {
      const client = this.supabaseService.getClient();
      const field = success ? 'successful_resets' : 'failed_resets';

      // Get current settings
      const { data: settings, error: fetchError } = await client
        .from('seed_reset_settings')
        .select('id, total_resets, successful_resets, failed_resets')
        .limit(1)
        .single();

      if (fetchError) {
        if (fetchError.code === 'PGRST116') {
          // No settings yet - create with initial values
          await client.from('seed_reset_settings').insert({
            enabled: true,
            interval: '0 0 * * *',
            exclusions: [],
            max_retries: 3,
            retry_on_failure: true,
            total_resets: 1,
            successful_resets: success ? 1 : 0,
            failed_resets: success ? 0 : 1,
            updated_at: new Date().toISOString(),
          });
          return;
        }
        throw fetchError;
      }

      // Update existing settings
      const updates: Record<string, unknown> = {
        total_resets: (settings.total_resets || 0) + 1,
        updated_at: new Date().toISOString(),
      };

      if (success) {
        updates.successful_resets = (settings.successful_resets || 0) + 1;
      } else {
        updates.failed_resets = (settings.failed_resets || 0) + 1;
      }

      const { error } = await client
        .from('seed_reset_settings')
        .update(updates)
        .eq('id', settings.id);

      if (error) {
        this.logger.warn(`Failed to update reset counters: ${error.message}`);
      }
    } catch (error) {
      // Non-critical operation - log but don't throw
      this.logger.warn(
        `Failed to increment reset counters: ${(error as Error).message}`,
      );
    }
  }

  private async seedLinks(): Promise<{ seeded: number; skipped: number }> {
    const client = this.supabaseService.getClient();
    const rows = DEMO_LINKS.map(this.mapLink);

    const { data, error } = await client
      .from('links')
      .upsert(rows, { onConflict: 'id', ignoreDuplicates: false })
      .select('id');

    if (error) {
      this.logger.error(`Failed to seed demo links: ${error.message}`);
      // Return 0/total so the caller knows nothing was inserted
      return { seeded: 0, skipped: rows.length };
    }

    const seeded  = (data ?? []).length;
    const skipped = rows.length - seeded;
    return { seeded, skipped };
  }

  private async seedTransactions(): Promise<{ seeded: number; skipped: number }> {
    const client = this.supabaseService.getClient();
    const rows = DEMO_TRANSACTIONS.map(this.mapTransaction);

    const { data, error } = await client
      .from('transactions')
      .upsert(rows, { onConflict: 'id', ignoreDuplicates: false })
      .select('id');

    if (error) {
      this.logger.error(`Failed to seed demo transactions: ${error.message}`);
      return { seeded: 0, skipped: rows.length };
    }

    const seeded  = (data ?? []).length;
    const skipped = rows.length - seeded;
    return { seeded, skipped };
  }

  // Map camelCase fixture shapes → snake_case DB columns
  private mapLink(link: DemoLink): Record<string, unknown> {
    return {
      id:                link.id,
      slug:              link.slug,
      label:             link.label,
      asset_code:        link.assetCode,
      asset_issuer:      link.assetIssuer,
      amount:            link.amount,
      recipient_address: link.recipientAddress,
      memo:              link.memo,
      active:            link.active,
      created_at:        link.createdAt,
    };
  }

  private mapTransaction(tx: DemoTransaction): Record<string, unknown> {
    return {
      id:                tx.id,
      link_id:           tx.linkId,
      sender_address:    tx.senderAddress,
      recipient_address: tx.recipientAddress,
      asset_code:        tx.assetCode,
      asset_issuer:      tx.assetIssuer,
      amount:            tx.amount,
      stellar_tx_hash:   tx.stellarTxHash,
      status:            tx.status,
      created_at:        tx.createdAt,
    };
  }
}