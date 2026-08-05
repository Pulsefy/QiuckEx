import {
  BadRequestException,
  Injectable,
  Logger,
  NotFoundException,
} from '@nestjs/common';
import { EventEmitter2 } from '@nestjs/event-emitter';
import * as crypto from 'crypto';

import { AppConfigService } from '../config';
import { SupabaseService } from '../supabase/supabase.service';
import {
  ContractSpecResponseDto,
  ContractSpecsResponseDto,
  StoreContractSpecDto,
} from './dto/contract-spec.dto';
import { ContractRegistryService } from './contract-registry.service';

interface SpecRecord {
  contractName: string;
  network: string;
  contractId: string;
  wasmHash: string;
  contractVersion: number;
  schemaVersion: string;
  methods: Array<{
    name: string;
    args: string[];
    returns: string;
    description?: string;
    access?: Record<string, boolean>;
  }>;
  events: Array<{
    name: string;
    fields: string[];
    description?: string;
  }>;
  storage: Array<{
    name: string;
    fields: string[];
    description?: string;
  }>;
  metadata: Record<string, unknown>;
  version: number;
  updatedAt: string;
}

@Injectable()
export class ContractSpecService {
  private readonly logger = new Logger(ContractSpecService.name);
  private readonly specCache = new Map<string, SpecRecord>();
  private cacheVersion = 0;

  constructor(
    private readonly supabaseService: SupabaseService,
    private readonly configService: AppConfigService,
    private readonly registryService: ContractRegistryService,
    private readonly eventEmitter: EventEmitter2,
  ) {}

  /**
   * Get contract spec for a specific contract name
   */
  async getContractSpec(name: string): Promise<ContractSpecResponseDto> {
    const normalizedName = name.trim().toLowerCase();
    const record = await this.getSpecRecord(normalizedName);

    if (!record) {
      throw new NotFoundException(
        `No contract spec found for contract "${name}"`,
      );
    }

    // Verify the spec matches the current registry entry
    const deployment = await this.registryService.getDeploymentByName(name);
    if (
      deployment.contractId !== record.contractId ||
      deployment.wasmHash !== record.wasmHash ||
      deployment.contractVersion !== record.contractVersion
    ) {
      // Registry entry is newer than cached spec, fetch latest
      const updated = await this.fetchAndStoreSpec(normalizedName);
      if (!updated) {
        throw new NotFoundException(
          `Contract "${name}" exists in registry but spec is unavailable`,
        );
      }
      return this.toResponseDto(updated);
    }

    return this.toResponseDto(record);
  }

  /**
   * Get all contract specs for the current network
   */
  async getAllSpecs(): Promise<ContractSpecsResponseDto> {
    const records = await this.getAllSpecRecords();
    const specs: Record<string, ContractSpecResponseDto> = {};

    for (const record of records) {
      specs[record.contractName] = this.toResponseDto(record);
    }

    const version = records.reduce(
      (max, record) => Math.max(max, record.version),
      this.cacheVersion,
    );

    return {
      network: this.configService.network,
      etag: this.buildEtag(version),
      version,
      specs,
    };
  }

  /**
   * Store or update contract spec in the registry
   */
  async storeContractSpec(
    dto: StoreContractSpecDto,
    actor: string = 'api',
  ): Promise<ContractSpecResponseDto> {
    const normalizedName = dto.name.trim().toLowerCase();

    // Verify contract exists in registry
    let deployment;
    try {
      deployment = await this.registryService.getDeploymentByName(dto.name);
    } catch {
      throw new BadRequestException(
        `Contract "${dto.name}" must be registered before storing its spec`,
      );
    }

    const now = new Date().toISOString();
    const record: SpecRecord = {
      contractName: normalizedName,
      network: this.configService.network,
      contractId: deployment.contractId,
      wasmHash: deployment.wasmHash,
      contractVersion: deployment.contractVersion,
      schemaVersion: deployment.schemaVersion || '1.0.0',
      methods: dto.methods,
      events: dto.events,
      storage: dto.storage,
      metadata: dto.metadata || {},
      version: Date.now(),
      updatedAt: now,
    };

    await this.persistSpec(record);
    this.updateCache(record);

    this.logger.log(
      `Stored contract spec for ${normalizedName} at version ${record.version}`,
    );

    return this.toResponseDto(record);
  }

  /**
   * Fetch and store spec from contract RPC if available
   */
  private async fetchAndStoreSpec(
    contractName: string,
  ): Promise<SpecRecord | null> {
    try {
      // This would call the contract to get its spec
      // For now, we return null to indicate spec needs to be published
      // with the contract deployment
      this.logger.debug(
        `Attempting to fetch spec from contract ${contractName} via RPC`,
      );
      return null;
    } catch (error) {
      this.logger.error(
        `Failed to fetch spec for ${contractName}: ${(error as Error).message}`,
      );
      return null;
    }
  }

  private async getSpecRecord(
    contractName: string,
  ): Promise<SpecRecord | undefined> {
    // Check cache first
    const cached = this.specCache.get(contractName);
    if (cached) {
      return cached;
    }

    // Fall back to database
    try {
      const client = this.supabaseService.getClient();
      const { data, error } = await client
        .from('contract_spec_entries')
        .select('*')
        .eq('contract_name', contractName)
        .eq('network', this.configService.network)
        .order('version', { ascending: false })
        .limit(1)
        .single();

      if (error) {
        if (error.code === 'PGRST116') {
          // No rows found
          return undefined;
        }
        throw error;
      }

      if (!data) {
        return undefined;
      }

      const record = this.mapToSpecRecord(data);
      this.specCache.set(contractName, record);
      return record;
    } catch (error) {
      this.logger.warn(
        `Failed to fetch spec for ${contractName}: ${(error as Error).message}`,
      );
      return this.specCache.get(contractName);
    }
  }

  private async getAllSpecRecords(): Promise<SpecRecord[]> {
    try {
      const client = this.supabaseService.getClient();
      const { data, error } = await client
        .from('contract_spec_entries')
        .select('*')
        .eq('network', this.configService.network);

      if (error) throw error;

      if (!data || data.length === 0) {
        return Array.from(this.specCache.values());
      }

      const records = data.map((row) => this.mapToSpecRecord(row));
      // Update cache with latest
      for (const record of records) {
        this.specCache.set(record.contractName, record);
      }
      return records;
    } catch (error) {
      this.logger.warn(
        `Failed to fetch specs: ${(error as Error).message}`,
      );
      return Array.from(this.specCache.values());
    }
  }

  private async persistSpec(record: SpecRecord): Promise<void> {
    try {
      const client = this.supabaseService.getClient();
      const { error } = await client.from('contract_spec_entries').insert({
        contract_name: record.contractName,
        network: record.network,
        contract_id: record.contractId,
        wasm_hash: record.wasmHash,
        contract_version: record.contractVersion,
        schema_version: record.schemaVersion,
        methods: record.methods,
        events: record.events,
        storage: record.storage,
        metadata: record.metadata,
        version: record.version,
        updated_at: record.updatedAt,
      });

      if (error) throw error;
    } catch (error) {
      this.logger.error(
        `Failed to persist spec for ${record.contractName}: ${(error as Error).message}`,
      );
      throw new Error(`Failed to store contract spec: ${(error as Error).message}`);
    }
  }

  private updateCache(record: SpecRecord): void {
    this.specCache.set(record.contractName, record);
    this.cacheVersion = Math.max(this.cacheVersion, record.version);
  }

  private mapToSpecRecord(data: Record<string, unknown>): SpecRecord {
    return {
      contractName: String(data.contract_name),
      network: String(data.network),
      contractId: String(data.contract_id),
      wasmHash: String(data.wasm_hash),
      contractVersion: Number(data.contract_version),
      schemaVersion: String(data.schema_version || '1.0.0'),
      methods: this.parseMethods(data.methods),
      events: this.parseEvents(data.events),
      storage: this.parseStorage(data.storage),
      metadata: this.parseMetadata(data.metadata),
      version: Number(data.version),
      updatedAt: String(data.updated_at),
    };
  }

  private parseMethods(methods: unknown): SpecRecord['methods'] {
    if (!Array.isArray(methods)) {
      return [];
    }
    return methods.map((method) => ({
      name: String(method.name || ''),
      args: Array.isArray(method.args) ? method.args.map(String) : [],
      returns: String(method.returns || 'void'),
      description: method.description ? String(method.description) : undefined,
      access: method.access && typeof method.access === 'object'
        ? method.access as Record<string, boolean>
        : undefined,
    }));
  }

  private parseEvents(events: unknown): SpecRecord['events'] {
    if (!Array.isArray(events)) {
      return [];
    }
    return events.map((event) => ({
      name: String(event.name || ''),
      fields: Array.isArray(event.fields) ? event.fields.map(String) : [],
      description: event.description ? String(event.description) : undefined,
    }));
  }

  private parseStorage(storage: unknown): SpecRecord['storage'] {
    if (!Array.isArray(storage)) {
      return [];
    }
    return storage.map((item) => ({
      name: String(item.name || ''),
      fields: Array.isArray(item.fields) ? item.fields.map(String) : [],
      description: item.description ? String(item.description) : undefined,
    }));
  }

  private parseMetadata(metadata: unknown): Record<string, unknown> {
    if (metadata && typeof metadata === 'object') {
      return metadata as Record<string, unknown>;
    }
    return {};
  }

  private toResponseDto(record: SpecRecord): ContractSpecResponseDto {
    return {
      name: record.contractName,
      contractId: record.contractId,
      wasmHash: record.wasmHash,
      version: record.contractVersion,
      schemaVersion: record.schemaVersion,
      methods: record.methods,
      events: record.events,
      storage: record.storage,
      metadata: record.metadata,
      updatedAt: record.updatedAt,
      etag: this.buildEtag(record.contractVersion, record.contractName),
    };
  }

  private buildEtag(version: number, name?: string): string {
    const identifier = name || 'all';
    return `W/"contract-spec-${this.configService.network}-${identifier}-${version}"`;
  }

  /**
   * Invalidate cache for a specific contract or all contracts
   */
  invalidateCache(contractName?: string): void {
    if (contractName) {
      this.specCache.delete(contractName.toLowerCase());
      this.logger.debug(`Invalidated spec cache for ${contractName}`);
    } else {
      this.specCache.clear();
      this.logger.debug('Invalidated all spec cache');
    }
  }

  /**
   * Get current cache version for ETag generation
   */
  getCacheVersion(): number {
    let maxVersion = this.cacheVersion;
    for (const record of this.specCache.values()) {
      if (record.version > maxVersion) {
        maxVersion = record.version;
      }
    }
    return maxVersion;
  }
}