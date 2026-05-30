import {
  BadRequestException,
  Injectable,
  Logger,
  NotFoundException,
} from '@nestjs/common';

import { AuditService } from '../audit/audit.service';
import { AppConfigService } from '../config';
import { SupabaseService } from '../supabase/supabase.service';
import {
  ContractRegistryEntryDto,
  PublishContractRegistryDto,
  RollbackContractRegistryDto,
} from './dto/contract-registry.dto';

interface RegistryRecord {
  name: string;
  network: string;
  contractId: string;
  wasmHash: string;
  contractVersion: number;
  deploymentId?: string;
  metadata?: Record<string, unknown>;
  publishedBy: string;
  version: number;
  createdAt: string;
  updatedAt: string;
  networkPassphrase: string;
  active: boolean;
}

@Injectable()
export class ContractRegistryService {
  private readonly logger = new Logger(ContractRegistryService.name);
  private readonly fallbackStore = new Map<string, RegistryRecord[]>();
  private readonly expectedContracts: string[];
  private fallbackVersion = 0;

  constructor(
    private readonly supabaseService: SupabaseService,
    private readonly auditService: AuditService,
    private readonly configService: AppConfigService,
  ) {
    this.expectedContracts = (process.env.CONTRACT_REGISTRY_EXPECTED_SET ?? 'quickex')
      .split(',')
      .map((value) => value.trim().toLowerCase())
      .filter(Boolean);
  }

  async getRegistry() {
    const records = await this.readRecords();
    const active = records.filter((record) => record.active);
    const data = Object.fromEntries(
      active.map((record) => [
        record.name,
        {
          id: record.contractId,
          wasmHash: record.wasmHash,
          version: record.contractVersion,
          deploymentId: record.deploymentId,
          updatedAt: record.updatedAt,
          metadata: record.metadata ?? {},
        },
      ]),
    );

    const version = active.reduce(
      (max, record) => Math.max(max, record.version),
      this.fallbackVersion,
    );

    return {
      network: this.configService.network,
      authoritative: true,
      version,
      etag: this.buildEtag(version),
      data,
    };
  }

  async publish(
    dto: PublishContractRegistryDto,
    actor = 'deployment_automation',
  ) {
    this.validatePassphrase(dto.networkPassphrase);
    this.validateContractSet(dto.contracts);

    const current = await this.readRecords();
    let nextVersion = current.reduce(
      (max, record) => Math.max(max, record.version),
      this.fallbackVersion,
    );

    const now = new Date().toISOString();
    const names = new Set(dto.contracts.map((contract) => contract.name.toLowerCase()));
    const retained = current.map((record) =>
      names.has(record.name) ? { ...record, active: false, updatedAt: now } : record,
    );

    const published: RegistryRecord[] = dto.contracts.map((contract) => {
      nextVersion += 1;
      return this.toRecord(contract, dto, actor, nextVersion, now);
    });

    const merged = [...retained, ...published];
    this.fallbackVersion = nextVersion;
    this.writeFallback(merged);
    await this.persistSnapshot(merged);
    await this.auditService.log(
      'contract_registry',
      'registry.publish',
      dto.deploymentId,
      {
        actor,
        version: nextVersion,
        contracts: published.map((record) => ({
          name: record.name,
          contractId: record.contractId,
          wasmHash: record.wasmHash,
          contractVersion: record.contractVersion,
        })),
      },
    );

    this.logger.log(
      `Published ${published.length} contract registry entr${published.length === 1 ? 'y' : 'ies'} at version ${nextVersion}`,
    );

    return this.getRegistry();
  }

  async rollback(
    dto: RollbackContractRegistryDto,
    actor = 'deployment_automation',
  ) {
    const records = await this.readRecords();
    const targetName = dto.name.toLowerCase();
    const candidate = records.find(
      (record) => record.name === targetName && record.contractVersion === dto.version,
    );

    if (!candidate) {
      throw new NotFoundException(
        `No registry entry found for ${dto.name} at version ${dto.version}`,
      );
    }

    const now = new Date().toISOString();
    const nextVersion = records.reduce(
      (max, record) => Math.max(max, record.version),
      this.fallbackVersion,
    ) + 1;

    const updated = records.map((record) => {
      if (record.name !== targetName) return record;
      return {
        ...record,
        active: record.contractVersion === dto.version,
        updatedAt: now,
        version: record.contractVersion === dto.version ? nextVersion : record.version,
      };
    });

    this.fallbackVersion = Math.max(this.fallbackVersion, nextVersion);
    this.writeFallback(updated);
    await this.persistSnapshot(updated);
    await this.auditService.log(
      'contract_registry',
      'registry.rollback',
      dto.name,
      { actor, requestedVersion: dto.version, registryVersion: nextVersion },
    );

    return this.getRegistry();
  }

  private validatePassphrase(passphrase: string): void {
    const expected =
      this.configService.network === 'mainnet'
        ? 'Public Global Stellar Network ; September 2015'
        : 'Test SDF Network ; September 2015';

    if (passphrase !== expected) {
      throw new BadRequestException(
        `networkPassphrase does not match the active ${this.configService.network} network`,
      );
    }
  }

  private validateContractSet(contracts: ContractRegistryEntryDto[]): void {
    const normalized = contracts.map((contract) => contract.name.toLowerCase()).sort();
    const expected = [...this.expectedContracts].sort();

    if (normalized.length !== expected.length) {
      throw new BadRequestException(
        `Expected ${expected.length} contract entries (${expected.join(', ')}) but received ${normalized.length}`,
      );
    }

    for (let index = 0; index < expected.length; index += 1) {
      if (normalized[index] !== expected[index]) {
        throw new BadRequestException(
          `Unexpected contract set. Expected ${expected.join(', ')}`,
        );
      }
    }
  }

  private toRecord(
    contract: ContractRegistryEntryDto,
    dto: PublishContractRegistryDto,
    actor: string,
    version: number,
    timestamp: string,
  ): RegistryRecord {
    return {
      name: contract.name.toLowerCase(),
      network: this.configService.network,
      contractId: contract.contractId,
      wasmHash: contract.wasmHash,
      contractVersion: contract.contractVersion ?? 1,
      deploymentId: dto.deploymentId,
      metadata: contract.metadata,
      publishedBy: actor,
      version,
      createdAt: timestamp,
      updatedAt: timestamp,
      networkPassphrase: dto.networkPassphrase,
      active: true,
    };
  }

  private buildEtag(version: number): string {
    return `W/\"contract-registry-${this.configService.network}-${version}\"`;
  }

  private fallbackKey(): string {
    return `contract-registry:${this.configService.network}`;
  }

  private writeFallback(records: RegistryRecord[]): void {
    this.fallbackStore.set(this.fallbackKey(), records);
  }

  private async readRecords(): Promise<RegistryRecord[]> {
    const fallback = this.fallbackStore.get(this.fallbackKey()) ?? [];

    try {
      const client = this.supabaseService.getClient();
      const { data, error } = await client
        .from('contract_registry_entries')
        .select('*')
        .eq('network', this.configService.network)
        .order('version', { ascending: true });

      if (error) throw error;
      if (!data || data.length === 0) return fallback;

      return data.map((row) => ({
        name: String(row.contract_name),
        network: String(row.network),
        contractId: String(row.contract_id),
        wasmHash: String(row.wasm_hash),
        contractVersion: Number(row.contract_version),
        deploymentId: row.deployment_id ? String(row.deployment_id) : undefined,
        metadata:
          row.metadata && typeof row.metadata === 'object'
            ? (row.metadata as Record<string, unknown>)
            : undefined,
        publishedBy: String(row.published_by ?? 'unknown'),
        version: Number(row.version),
        createdAt: String(row.created_at),
        updatedAt: String(row.updated_at),
        networkPassphrase: String(row.network_passphrase),
        active: Boolean(row.is_active),
      }));
    } catch (error) {
      this.logger.warn(
        `Falling back to in-memory contract registry: ${(error as Error).message}`,
      );
      return fallback;
    }
  }

  private async persistSnapshot(records: RegistryRecord[]): Promise<void> {
    try {
      const client = this.supabaseService.getClient();
      await client.from('contract_registry_entries').delete().eq('network', this.configService.network);
      const { error } = await client.from('contract_registry_entries').insert(
        records.map((record) => ({
          contract_name: record.name,
          network: record.network,
          contract_id: record.contractId,
          wasm_hash: record.wasmHash,
          contract_version: record.contractVersion,
          deployment_id: record.deploymentId ?? null,
          metadata: record.metadata ?? {},
          published_by: record.publishedBy,
          version: record.version,
          created_at: record.createdAt,
          updated_at: record.updatedAt,
          network_passphrase: record.networkPassphrase,
          is_active: record.active,
        })),
      );

      if (error) throw error;
    } catch (error) {
      this.logger.warn(
        `Unable to persist contract registry snapshot: ${(error as Error).message}`,
      );
    }
  }
}
