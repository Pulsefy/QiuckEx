import {
  BadRequestException,
  Injectable,
  Logger,
  NotFoundException,
} from '@nestjs/common';
import { EventEmitter2 } from '@nestjs/event-emitter';

import { AuditService } from '../audit/audit.service';
import { AppConfigService } from '../config';
import { SupabaseService } from '../supabase/supabase.service';
import {
  ContractRegistryEntryDto,
  ContractSchemaCompatibilityDto,
  PublishContractRegistryDto,
  RollbackContractRegistryDto,
  UpsertContractDeploymentDto,
} from './dto';
import {
  ContractRegistryPublishedEvent,
  ContractRegistryRolledBackEvent,
  ContractRegistryPublishedEventPayload,
  ContractRegistryRolledBackEventPayload,
} from '../events/contract-registry.events';
import {
  ContractChangeWebhookService,
} from './contract-change-webhook.service';
import {
  ContractChangeWebhookDispatcher,
} from './contract-change-webhook.dispatcher';

interface RegistryRecord {
  name: string;
  network: string;
  contractId: string;
  previousContractId?: string;
  effectiveLedger?: number;
  effectiveTime?: string;
  wasmHash: string;
  contractVersion: number;
  schemaVersion: string;
  schemaCompatibility: ContractSchemaCompatibilityDto;
  deploymentId?: string;
  initParams?: Record<string, unknown>;
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
    private readonly eventEmitter: EventEmitter2,
    private readonly contractChangeWebhookService: ContractChangeWebhookService,
    private readonly webhookDispatcher: ContractChangeWebhookDispatcher,
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
          schemaVersion: record.schemaVersion,
          schemaCompatibility: record.schemaCompatibility,
          networkPassphrase: record.networkPassphrase,
          deploymentId: record.deploymentId,
          initParams: record.initParams ?? {},
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

  async getDeployments() {
    const records = await this.readRecords();
    const deployments = records
      .filter((record) => record.active)
      .sort((left, right) => left.name.localeCompare(right.name))
      .map((record) => this.toDeploymentItem(record));

    return {
      network: this.configService.network,
      deployments,
    };
  }

  async getDeploymentByName(name: string) {
    const records = await this.readRecords();
    const normalizedName = name.trim().toLowerCase();
    const record = records.find(
      (candidate) => candidate.active && candidate.name === normalizedName,
    );

    if (!record) {
      throw new NotFoundException(
        `No active deployment metadata found for contract ${name}`,
      );
    }

    return this.toDeploymentItem(record);
  }

  async upsertDeployment(
    dto: UpsertContractDeploymentDto,
    actor = 'deployment_automation',
  ) {
    if (dto.network !== this.configService.network) {
      throw new BadRequestException(
        `network must match active backend network (${this.configService.network})`,
      );
    }

    this.validatePassphrase(dto.networkPassphrase);
    const normalizedName = dto.name.trim().toLowerCase();
    const now = new Date().toISOString();
    const records = await this.readRecords();

    const currentActive = records.find(
      (record) => record.active && record.name === normalizedName,
    );

    const nextVersion =
      records.reduce((max, record) => Math.max(max, record.version), this.fallbackVersion) +
      1;

    const retained = records.map((record) => {
      if (record.name !== normalizedName) return record;
      return { ...record, active: false, updatedAt: now };
    });

    const nextRecord: RegistryRecord = {
      name: normalizedName,
      network: dto.network,
      contractId: dto.contractId,
      previousContractId: undefined,
      effectiveLedger: undefined,
      effectiveTime: undefined,
      wasmHash: dto.wasmHash,
      contractVersion: dto.contractVersion ?? (currentActive?.contractVersion ?? 1),
      schemaVersion: dto.schemaVersion,
      schemaCompatibility: dto.schemaCompatibility,
      deploymentId: dto.deploymentId,
      initParams: dto.initParams,
      metadata: dto.metadata,
      publishedBy: actor,
      version: nextVersion,
      createdAt: now,
      updatedAt: now,
      networkPassphrase: dto.networkPassphrase,
      active: true,
    };

    const updated = [...retained, nextRecord];
    this.fallbackVersion = nextVersion;
    this.writeFallback(updated);
    await this.persistSnapshot(updated);

    await this.auditService.log(
      'contract_registry',
      'registry.deployment.upsert',
      normalizedName,
      {
        actor,
        network: dto.network,
        registryVersion: nextVersion,
        before: currentActive
          ? {
              contractId: currentActive.contractId,
              wasmHash: currentActive.wasmHash,
              contractVersion: currentActive.contractVersion,
              schemaVersion: currentActive.schemaVersion,
              schemaCompatibility: currentActive.schemaCompatibility,
              networkPassphrase: currentActive.networkPassphrase,
            }
          : null,
        after: {
          contractId: nextRecord.contractId,
          wasmHash: nextRecord.wasmHash,
          contractVersion: nextRecord.contractVersion,
          schemaVersion: nextRecord.schemaVersion,
          schemaCompatibility: nextRecord.schemaCompatibility,
          networkPassphrase: nextRecord.networkPassphrase,
        },
      },
    );

    return this.toDeploymentItem(nextRecord);
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

    await this.eventEmitter.emit(
      ContractRegistryPublishedEvent,
      new ContractRegistryPublishedEventPayload(
        nextVersion,
        published.map((record) => ({
          name: record.name,
          contractId: record.contractId,
          wasmHash: record.wasmHash,
          contractVersion: record.contractVersion,
          deploymentId: record.deploymentId,
        })),
        actor,
      ),
    );

    const enabledWebhooks = await this.contractChangeWebhookService.getEnabledWebhooks();
    if (enabledWebhooks.length > 0) {
      this.webhookDispatcher.dispatch(enabledWebhooks, {
        version: nextVersion,
        event: 'contract_registry.published',
        actor,
        deploymentId: dto.deploymentId,
        contracts: published.map((record) => ({
          name: record.name,
          contractId: record.contractId,
          wasmHash: record.wasmHash,
          contractVersion: record.contractVersion,
          deploymentId: record.deploymentId,
        })),
      });
    }

    return this.getRegistry();
  }

  async finalizeDualRead(
    contractName: string,
    actor = 'deployment_automation',
  ) {
    const records = await this.readRecords();
    const targetName = contractName.toLowerCase();
    const candidate = records.find(
      (record) => record.name === targetName && record.active,
    );

    if (!candidate) {
      throw new NotFoundException(
        `No active registry entry found for ${contractName}`,
      );
    }

    if (!candidate.previousContractId) {
      throw new BadRequestException(
        `Registry entry for ${contractName} is not in a dual-read transition window`,
      );
    }

    const now = new Date().toISOString();
    const updated = records.map((record) => {
      if (record.name !== targetName) return record;
      return {
        ...record,
        previousContractId: undefined,
        effectiveLedger: record.effectiveLedger,
        effectiveTime: now,
        updatedAt: now,
      };
    });

    this.writeFallback(updated);
    await this.persistSnapshot(updated);
    await this.auditService.log(
      'contract_registry',
      'registry.finalize_dual_read',
      contractName,
      {
        actor,
        finalizedAt: now,
      },
    );

    this.logger.log(
      `Finalized dual-read for contract ${contractName} at timestamp ${now}`,
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

    await this.eventEmitter.emit(
      ContractRegistryRolledBackEvent,
      new ContractRegistryRolledBackEventPayload(
        targetName,
        nextVersion,
        candidate.contractId,
        candidate.wasmHash,
        candidate.contractVersion,
        actor,
      ),
    );

    const enabledWebhooks = await this.contractChangeWebhookService.getEnabledWebhooks();
    if (enabledWebhooks.length > 0) {
      this.webhookDispatcher.dispatch(enabledWebhooks, {
        version: nextVersion,
        event: 'contract_registry.rolled_back',
        contractName: targetName,
        contractId: candidate.contractId,
        wasmHash: candidate.wasmHash,
        contractVersion: candidate.contractVersion,
        actor,
      });
    }

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
      schemaVersion: contract.schemaVersion ?? '1.0.0',
      schemaCompatibility: contract.schemaCompatibility ?? { min: '1.0.0', max: '1.0.0' },
      deploymentId: dto.deploymentId,
      initParams: contract.initParams,
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
        previousContractId: row.previous_contract_id ? String(row.previous_contract_id) : undefined,
        effectiveLedger: row.effective_ledger ? Number(row.effective_ledger) : undefined,
        effectiveTime: row.effective_time ? String(row.effective_time) : undefined,
        wasmHash: String(row.wasm_hash),
        contractVersion: Number(row.contract_version),
        schemaVersion: String(row.schema_version ?? '1.0.0'),
        schemaCompatibility: this.readSchemaCompatibility(row),
        deploymentId: row.deployment_id ? String(row.deployment_id) : undefined,
        initParams:
          row.init_params && typeof row.init_params === 'object'
            ? (row.init_params as Record<string, unknown>)
            : undefined,
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
          previous_contract_id: record.previousContractId ?? null,
          effective_ledger: record.effectiveLedger ?? null,
          effective_time: record.effectiveTime ?? null,
          wasm_hash: record.wasmHash,
          contract_version: record.contractVersion,
          schema_version: record.schemaVersion,
          schema_compatibility: record.schemaCompatibility,
          deployment_id: record.deploymentId ?? null,
          init_params: record.initParams ?? {},
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

  private toDeploymentItem(record: RegistryRecord) {
    return {
      name: record.name,
      network: record.network,
      networkPassphrase: record.networkPassphrase,
      contractId: record.contractId,
      wasmHash: record.wasmHash,
      contractVersion: record.contractVersion,
      schemaVersion: record.schemaVersion,
      schemaCompatibility: record.schemaCompatibility,
      initParams: record.initParams ?? {},
      metadata: record.metadata ?? {},
      updatedAt: record.updatedAt,
      registryVersion: record.version,
      deploymentId: record.deploymentId,
    };
  }

  private readSchemaCompatibility(row: Record<string, unknown>): ContractSchemaCompatibilityDto {
    const fallback: ContractSchemaCompatibilityDto = { min: '1.0.0', max: '1.0.0' };

    const raw = row.schema_compatibility;
    if (!raw || typeof raw !== 'object') return fallback;

    const candidate = raw as Record<string, unknown>;
    const min = typeof candidate.min === 'string' ? candidate.min : fallback.min;
    const max = typeof candidate.max === 'string' ? candidate.max : fallback.max;
    return { min, max };
  }
}
