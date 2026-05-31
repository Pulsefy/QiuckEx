/**
 * @file demo/demo.fixtures.ts
 *
 * Deterministic fixtures for testnet demo mode (#509).
 * All IDs and amounts are fixed constants so repeated seeds produce identical
 * database state.  Never change existing entries — only append new ones so
 * that test flows remain stable across runs.
 */

export interface DemoLink {
  id: string;
  slug: string;
  label: string;
  assetCode: string;
  assetIssuer: string | null;
  amount: string;
  recipientAddress: string;
  memo: string | null;
  active: boolean;
  createdAt: string;
}

export interface DemoTransaction {
  id: string;
  linkId: string;
  senderAddress: string;
  recipientAddress: string;
  assetCode: string;
  assetIssuer: string | null;
  amount: string;
  stellarTxHash: string;
  status: 'success' | 'pending' | 'failed';
  createdAt: string;
}

// ---------------------------------------------------------------------------
// Demo Stellar addresses (testnet-only, no real funds)
// ---------------------------------------------------------------------------

export const DEMO_ADDRESSES = {
  ALICE:    'GDEMOALICE000000000000000000000000000000000000000000000001',
  BOB:      'GDEMOBOB0000000000000000000000000000000000000000000000000002',
  MERCHANT: 'GDEMO_MERCHANT00000000000000000000000000000000000000000003',
  ESCROW:   'GDEMO_ESCROW000000000000000000000000000000000000000000000004',
} as const;

export const DEMO_USDC_ISSUER = 'GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5';

// ---------------------------------------------------------------------------
// Payment links
// ---------------------------------------------------------------------------

export const DEMO_LINKS: readonly DemoLink[] = [
  {
    id:               'demo_link_001',
    slug:             'demo-xlm-tip',
    label:            'Demo XLM Tip Jar',
    assetCode:        'XLM',
    assetIssuer:      null,
    amount:           '10.0000000',
    recipientAddress: DEMO_ADDRESSES.ALICE,
    memo:             'Demo tip — testnet only',
    active:           true,
    createdAt:        '2024-01-01T00:00:00.000Z',
  },
  {
    id:               'demo_link_002',
    slug:             'demo-usdc-payment',
    label:            'Demo USDC Payment',
    assetCode:        'USDC',
    assetIssuer:      DEMO_USDC_ISSUER,
    amount:           '25.0000000',
    recipientAddress: DEMO_ADDRESSES.BOB,
    memo:             'Demo USDC — testnet only',
    active:           true,
    createdAt:        '2024-01-01T01:00:00.000Z',
  },
  {
    id:               'demo_link_003',
    slug:             'demo-merchant-checkout',
    label:            'Demo Merchant Checkout',
    assetCode:        'USDC',
    assetIssuer:      DEMO_USDC_ISSUER,
    amount:           '99.9900000',
    recipientAddress: DEMO_ADDRESSES.MERCHANT,
    memo:             'INV-DEMO-001',
    active:           true,
    createdAt:        '2024-01-01T02:00:00.000Z',
  },
  {
    id:               'demo_link_004',
    slug:             'demo-expired-link',
    label:            'Demo Expired Link (inactive)',
    assetCode:        'XLM',
    assetIssuer:      null,
    amount:           '5.0000000',
    recipientAddress: DEMO_ADDRESSES.ALICE,
    memo:             null,
    active:           false,
    createdAt:        '2024-01-01T03:00:00.000Z',
  },
] as const;

// ---------------------------------------------------------------------------
// Sample transaction history
// ---------------------------------------------------------------------------

export const DEMO_TRANSACTIONS: readonly DemoTransaction[] = [
  {
    id:               'demo_tx_001',
    linkId:           'demo_link_001',
    senderAddress:    DEMO_ADDRESSES.BOB,
    recipientAddress: DEMO_ADDRESSES.ALICE,
    assetCode:        'XLM',
    assetIssuer:      null,
    amount:           '10.0000000',
    stellarTxHash:    'aaaaaaaabbbbbbbbccccccccddddddddeeeeeeeeffffffff0000000011111111',
    status:           'success',
    createdAt:        '2024-01-02T10:00:00.000Z',
  },
  {
    id:               'demo_tx_002',
    linkId:           'demo_link_002',
    senderAddress:    DEMO_ADDRESSES.ALICE,
    recipientAddress: DEMO_ADDRESSES.BOB,
    assetCode:        'USDC',
    assetIssuer:      DEMO_USDC_ISSUER,
    amount:           '25.0000000',
    stellarTxHash:    '1111111122222222333333334444444455555555666666667777777788888888',
    status:           'success',
    createdAt:        '2024-01-02T11:00:00.000Z',
  },
  {
    id:               'demo_tx_003',
    linkId:           'demo_link_003',
    senderAddress:    DEMO_ADDRESSES.ALICE,
    recipientAddress: DEMO_ADDRESSES.MERCHANT,
    assetCode:        'USDC',
    assetIssuer:      DEMO_USDC_ISSUER,
    amount:           '99.9900000',
    stellarTxHash:    '9999999988888888777777776666666655555555444444443333333322222222',
    status:           'pending',
    createdAt:        '2024-01-02T12:00:00.000Z',
  },
  {
    id:               'demo_tx_004',
    linkId:           'demo_link_001',
    senderAddress:    DEMO_ADDRESSES.MERCHANT,
    recipientAddress: DEMO_ADDRESSES.ALICE,
    assetCode:        'XLM',
    assetIssuer:      null,
    amount:           '10.0000000',
    stellarTxHash:    'deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef',
    status:           'failed',
    createdAt:        '2024-01-02T13:00:00.000Z',
  },
] as const;/**
 * @file demo/demo.service.ts
 *
 * Seeds and clears deterministic demo data for testnet demo mode (#509).
 * All public methods throw {@link ForbiddenException} when the active network
 * is not `"testnet"`, ensuring demo mode can never run on mainnet.
 */

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

@Injectable()
export class DemoService {
  private readonly logger = new Logger(DemoService.name);

  constructor(
    private readonly configService: ConfigService,
    private readonly supabaseService: SupabaseService,
  ) {}

  // ---------------------------------------------------------------------------
  // Guard
  // ---------------------------------------------------------------------------

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

  // ---------------------------------------------------------------------------
  // Seed
  // ---------------------------------------------------------------------------

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

  // ---------------------------------------------------------------------------
  // Clear
  // ---------------------------------------------------------------------------

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

  // ---------------------------------------------------------------------------
  // Status
  // ---------------------------------------------------------------------------

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

  // ---------------------------------------------------------------------------
  // Private helpers
  // ---------------------------------------------------------------------------

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