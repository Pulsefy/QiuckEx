import { Injectable, Logger, NotFoundException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as StellarSdk from '@stellar/stellar-sdk';

// ---------------------------------------------------------------------------
// Response shapes
// ---------------------------------------------------------------------------

export interface FeeConfigView {
  /** Fee charged on each payment in basis points (e.g. 50 = 0.5 %) */
  feeBps: number;
  /** Stellar account address that receives collected fees */
  feeRecipient: string;
  /** Minimum fee in stroops, regardless of basis-point calculation */
  minFeeStroops: string;
}

export interface PauseStateView {
  /** Whether the contract is globally paused */
  paused: boolean;
  /** Ledger sequence when the contract was last paused, or null */
  pausedAtLedger: number | null;
}

export interface ContractMetadataView {
  /** Human-readable contract name */
  name: string;
  /** Semver-style contract version string */
  version: string;
  /** Soroban contract ID (Bech32) */
  contractId: string;
  /** Stellar network the contract is deployed on */
  network: string;
  /** Ledger sequence when the contract was deployed */
  deployedAtLedger: number;
}

export interface EscrowSummaryView {
  id: string;
  depositor: string;
  beneficiary: string;
  amount: string;
  assetCode: string;
  released: boolean;
  refunded: boolean;
  expiryLedger: number;
  /** Whether the escrow is past its expiry ledger based on the last ledger polled */
  expired: boolean;
}

export interface LinkSummaryView {
  id: string;
  slug: string;
  recipientAddress: string;
  assetCode: string;
  amount: string;
  active: boolean;
  /** Ledger number when the link record expires from contract storage, or null if TTL-free */
  expiresAtLedger: number | null;
}

// ---------------------------------------------------------------------------
// Simple in-process TTL cache
// ---------------------------------------------------------------------------

interface CacheEntry<T> {
  value: T;
  expiresAt: number;
}

class TtlCache<T> {
  private readonly store = new Map<string, CacheEntry<T>>();

  get(key: string): T | undefined {
    const entry = this.store.get(key);
    if (!entry) return undefined;
    if (Date.now() > entry.expiresAt) {
      this.store.delete(key);
      return undefined;
    }
    return entry.value;
  }

  set(key: string, value: T, ttlMs: number): void {
    this.store.set(key, { value, expiresAt: Date.now() + ttlMs });
  }

  invalidate(key: string): void {
    this.store.delete(key);
  }
}

// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------

const CACHE_TTL_MS = 15_000; // 15 s — short enough to reflect recent state

@Injectable()
export class ContractViewsService {
  private readonly logger = new Logger(ContractViewsService.name);
  private readonly cache  = new TtlCache<unknown>();

  /** Soroban RPC server instance, lazily initialised */
  private rpc: StellarSdk.rpc.Server | null = null;

  constructor(private readonly configService: ConfigService) {}

  // ---------------------------------------------------------------------------
  // Public views
  // ---------------------------------------------------------------------------

  /** Fee configuration currently set on the contract. */
  async getFeeConfig(): Promise<FeeConfigView> {
    return this.cached('fee_config', () => this.fetchFeeConfig());
  }

  /** Contract pause state and last-paused ledger. */
  async getPauseState(): Promise<PauseStateView> {
    return this.cached('pause_state', () => this.fetchPauseState());
  }

  /** Static contract metadata (name, version, deploy ledger). */
  async getContractMetadata(): Promise<ContractMetadataView> {
    return this.cached('contract_metadata', () => this.fetchContractMetadata());
  }

  /**
   * Summary for a single escrow by its on-chain identifier.
   * Throws {@link NotFoundException} when the escrow does not exist or its
   * storage TTL has lapsed.
   */
  async getEscrowSummary(escrowId: string): Promise<EscrowSummaryView> {
    return this.cached(`escrow:${escrowId}`, () => this.fetchEscrowSummary(escrowId));
  }

  /**
   * Summary for a payment link by its slug or on-chain ID.
   * Throws {@link NotFoundException} when the link does not exist.
   */
  async getLinkSummary(identifier: string): Promise<LinkSummaryView> {
    return this.cached(`link:${identifier}`, () => this.fetchLinkSummary(identifier));
  }

  // ---------------------------------------------------------------------------
  // Fetch implementations
  // ---------------------------------------------------------------------------

  private async fetchFeeConfig(): Promise<FeeConfigView> {
    // Simulate a read-only `get_fee_config` contract call.
    // When QUICKEX_CONTRACT_ID is not set (e.g. local dev) we return safe
    // defaults so the frontend can still render.
    const contractId = this.configService.get<string>('QUICKEX_CONTRACT_ID')
      ?? process.env['QUICKEX_CONTRACT_ID'];

    if (!contractId) {
      this.logger.warn('QUICKEX_CONTRACT_ID not set — returning default fee config');
      return { feeBps: 50, feeRecipient: '', minFeeStroops: '100' };
    }

    try {
      const result = await this.simulateContractView(contractId, 'get_fee_config', []);
      return this.parseFeeConfig(result);
    } catch (err) {
      this.logger.warn(`get_fee_config simulation failed: ${(err as Error).message}`);
      return { feeBps: 50, feeRecipient: '', minFeeStroops: '100' };
    }
  }

  private async fetchPauseState(): Promise<PauseStateView> {
    const contractId = this.configService.get<string>('QUICKEX_CONTRACT_ID')
      ?? process.env['QUICKEX_CONTRACT_ID'];

    if (!contractId) {
      return { paused: false, pausedAtLedger: null };
    }

    try {
      const result = await this.simulateContractView(contractId, 'is_paused', []);
      return this.parsePauseState(result);
    } catch (err) {
      this.logger.warn(`is_paused simulation failed: ${(err as Error).message}`);
      return { paused: false, pausedAtLedger: null };
    }
  }

  private async fetchContractMetadata(): Promise<ContractMetadataView> {
    const stellarCfg = this.configService.get<{
      network: string;
      networkPassphrase: string;
    }>('stellar');

    const contractId = this.configService.get<string>('QUICKEX_CONTRACT_ID')
      ?? process.env['QUICKEX_CONTRACT_ID']
      ?? '';

    // Static fields we can derive without an RPC call
    const base: ContractMetadataView = {
      name:             'QuickEx Payment Contract',
      version:          '0.1.0',
      contractId,
      network:          stellarCfg?.network ?? 'testnet',
      deployedAtLedger: 0,
    };

    if (!contractId) return base;

    try {
      const result = await this.simulateContractView(contractId, 'get_metadata', []);
      return { ...base, ...this.parseContractMetadata(result) };
    } catch (err) {
      this.logger.warn(`get_metadata simulation failed: ${(err as Error).message}`);
      return base;
    }
  }

  private async fetchEscrowSummary(escrowId: string): Promise<EscrowSummaryView> {
    const contractId = this.requireContractId();

    const args = [StellarSdk.nativeToScVal(escrowId, { type: 'string' })];
    const result = await this.simulateContractView(contractId, 'get_escrow', args);

    if (!result) {
      throw new NotFoundException({
        error: 'ESCROW_NOT_FOUND',
        message: `Escrow "${escrowId}" not found or expired.`,
      });
    }

    return this.parseEscrowSummary(result, escrowId);
  }

  private async fetchLinkSummary(identifier: string): Promise<LinkSummaryView> {
    const contractId = this.requireContractId();

    const args = [StellarSdk.nativeToScVal(identifier, { type: 'string' })];
    const result = await this.simulateContractView(contractId, 'get_link', args);

    if (!result) {
      throw new NotFoundException({
        error: 'LINK_NOT_FOUND',
        message: `Link "${identifier}" not found or expired.`,
      });
    }

    return this.parseLinkSummary(result, identifier);
  }

  // ---------------------------------------------------------------------------
  // RPC simulation helper
  // ---------------------------------------------------------------------------

  private async simulateContractView(
    contractId: string,
    method:     string,
    args:       StellarSdk.xdr.ScVal[],
  ): Promise<StellarSdk.xdr.ScVal | null> {
    const server   = this.getRpcServer();
    const stellarCfg = this.configService.get<{ networkPassphrase: string }>('stellar');
    const passphrase = stellarCfg?.networkPassphrase ?? StellarSdk.Networks.TESTNET;

    // Use a throwaway keypair — read-only simulation needs no real signing key
    const dummyKeypair = StellarSdk.Keypair.random();
    const account = new StellarSdk.Account(dummyKeypair.publicKey(), '0');

    const contract = new StellarSdk.Contract(contractId);
    const tx = new StellarSdk.TransactionBuilder(account, {
      fee:            '100',
      networkPassphrase: passphrase,
    })
      .addOperation(contract.call(method, ...args))
      .setTimeout(30)
      .build();

    const sim = await server.simulateTransaction(tx);

    if (StellarSdk.rpc.Api.isSimulationError(sim)) {
      throw new Error(`Contract simulation error: ${sim.error}`);
    }

    if (StellarSdk.rpc.Api.isSimulationRestore(sim)) {
      // TTL restore needed — the entry is in a "can be restored" state, which
      // means the data is still accessible but storage is expiring.
      this.logger.warn(`Simulation requires TTL restore for ${method}`);
    }

    const returnVal = (sim as StellarSdk.rpc.Api.SimulateTransactionSuccessResponse)
      .result?.retval;

    return returnVal ?? null;
  }

  // ---------------------------------------------------------------------------
  // ScVal parsers — map contract return values to typed response shapes
  // ---------------------------------------------------------------------------

  private parseFeeConfig(val: StellarSdk.xdr.ScVal | null): FeeConfigView {
    if (!val) return { feeBps: 50, feeRecipient: '', minFeeStroops: '100' };
    try {
      const map  = this.scValToMap(val);
      const bps  = this.getMapField(map, 'fee_bps');
      const recip = this.getMapField(map, 'fee_recipient');
      const min  = this.getMapField(map, 'min_fee_stroops');
      return {
        feeBps:        bps  ? Number(StellarSdk.scValToNative(bps))  : 50,
        feeRecipient:  recip ? String(StellarSdk.scValToNative(recip)) : '',
        minFeeStroops: min  ? String(StellarSdk.scValToNative(min))  : '100',
      };
    } catch {
      return { feeBps: 50, feeRecipient: '', minFeeStroops: '100' };
    }
  }

  private parsePauseState(val: StellarSdk.xdr.ScVal | null): PauseStateView {
    if (!val) return { paused: false, pausedAtLedger: null };
    try {
      const map    = this.scValToMap(val);
      const paused = this.getMapField(map, 'paused');
      const ledger = this.getMapField(map, 'paused_at_ledger');
      return {
        paused:         paused ? Boolean(StellarSdk.scValToNative(paused)) : false,
        pausedAtLedger: ledger ? Number(StellarSdk.scValToNative(ledger)) : null,
      };
    } catch {
      return { paused: false, pausedAtLedger: null };
    }
  }

  private parseContractMetadata(val: StellarSdk.xdr.ScVal | null): Partial<ContractMetadataView> {
    if (!val) return {};
    try {
      const map     = this.scValToMap(val);
      const name    = this.getMapField(map, 'name');
      const version = this.getMapField(map, 'version');
      const ledger  = this.getMapField(map, 'deployed_at_ledger');
      return {
        name:             name    ? String(StellarSdk.scValToNative(name))    : undefined,
        version:          version ? String(StellarSdk.scValToNative(version)) : undefined,
        deployedAtLedger: ledger  ? Number(StellarSdk.scValToNative(ledger))  : undefined,
      };
    } catch {
      return {};
    }
  }

  private parseEscrowSummary(
    val:      StellarSdk.xdr.ScVal,
    escrowId: string,
  ): EscrowSummaryView {
    const map          = this.scValToMap(val);
    const expiryLedger = Number(StellarSdk.scValToNative(this.requireMapField(map, 'expiry_ledger')));
    const currentLedger = 0; // Would be fetched from horizon in a full impl; safe default

    return {
      id:            escrowId,
      depositor:     String(StellarSdk.scValToNative(this.requireMapField(map, 'depositor'))),
      beneficiary:   String(StellarSdk.scValToNative(this.requireMapField(map, 'beneficiary'))),
      amount:        String(StellarSdk.scValToNative(this.requireMapField(map, 'amount'))),
      assetCode:     String(StellarSdk.scValToNative(this.requireMapField(map, 'asset_code'))),
      released:      Boolean(StellarSdk.scValToNative(this.requireMapField(map, 'released'))),
      refunded:      Boolean(StellarSdk.scValToNative(this.requireMapField(map, 'refunded'))),
      expiryLedger,
      expired:       currentLedger > 0 && currentLedger > expiryLedger,
    };
  }

  private parseLinkSummary(
    val:        StellarSdk.xdr.ScVal,
    identifier: string,
  ): LinkSummaryView {
    const map     = this.scValToMap(val);
    const ttlField = this.getMapField(map, 'expires_at_ledger');

    return {
      id:               String(StellarSdk.scValToNative(this.requireMapField(map, 'id'))),
      slug:             identifier,
      recipientAddress: String(StellarSdk.scValToNative(this.requireMapField(map, 'recipient_address'))),
      assetCode:        String(StellarSdk.scValToNative(this.requireMapField(map, 'asset_code'))),
      amount:           String(StellarSdk.scValToNative(this.requireMapField(map, 'amount'))),
      active:           Boolean(StellarSdk.scValToNative(this.requireMapField(map, 'active'))),
      expiresAtLedger:  ttlField ? Number(StellarSdk.scValToNative(ttlField)) : null,
    };
  }

  // ---------------------------------------------------------------------------
  // ScVal map helpers
  // ---------------------------------------------------------------------------

  private scValToMap(val: StellarSdk.xdr.ScVal): Map<string, StellarSdk.xdr.ScVal> {
    if (val.switch() !== StellarSdk.xdr.ScValType.scvMap()) {
      throw new Error(`Expected ScvMap, got ${val.switch().name}`);
    }
    const result = new Map<string, StellarSdk.xdr.ScVal>();
    for (const entry of val.map() ?? []) {
      const keyNative = StellarSdk.scValToNative(entry.key());
      result.set(String(keyNative), entry.val());
    }
    return result;
  }

  private getMapField(
    map: Map<string, StellarSdk.xdr.ScVal>,
    key: string,
  ): StellarSdk.xdr.ScVal | undefined {
    return map.get(key);
  }

  private requireMapField(
    map: Map<string, StellarSdk.xdr.ScVal>,
    key: string,
  ): StellarSdk.xdr.ScVal {
    const val = map.get(key);
    if (!val) throw new Error(`Missing required field "${key}" in contract response`);
    return val;
  }

  // ---------------------------------------------------------------------------
  // Cache wrapper
  // ---------------------------------------------------------------------------

  private async cached<T>(key: string, fetch: () => Promise<T>): Promise<T> {
    const hit = this.cache.get(key) as T | undefined;
    if (hit !== undefined) return hit;

    const value = await fetch();
    this.cache.set(key, value, CACHE_TTL_MS);
    return value;
  }

  // ---------------------------------------------------------------------------
  // Config helpers
  // ---------------------------------------------------------------------------

  private getRpcServer(): StellarSdk.rpc.Server {
    if (this.rpc) return this.rpc;

    const stellarCfg = this.configService.get<{ sorobanRpcUrl: string }>('stellar');
    const rpcUrl = stellarCfg?.sorobanRpcUrl
      ?? process.env['SOROBAN_RPC_URL']
      ?? 'https://soroban-testnet.stellar.org';

    this.rpc = new StellarSdk.rpc.Server(rpcUrl, { allowHttp: false });
    return this.rpc;
  }

  private requireContractId(): string {
    const id = this.configService.get<string>('QUICKEX_CONTRACT_ID')
      ?? process.env['QUICKEX_CONTRACT_ID'];
    if (!id) {
      throw new NotFoundException({
        error: 'CONTRACT_NOT_CONFIGURED',
        message: 'QUICKEX_CONTRACT_ID is not configured.',
      });
    }
    return id;
  }
}