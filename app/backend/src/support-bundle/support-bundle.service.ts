import { Injectable, Logger } from '@nestjs/common';
import { AppConfigService } from '../config';
import { ContractRegistryService } from '../contracts/contract-registry.service';
import { IndexerLagService } from '../indexer-lag/indexer-lag.service';
import { IndexerCheckpointRepository } from '../ingestion/indexer-checkpoint.repository';
import { AuditService } from '../audit/audit.service';
import { AuditLog } from '../audit/audit.model';
import {
  SupportBundleDto,
  NetworkConfigDto,
  ContractRegistrySnapshotDto,
  IndexerStatusDto,
  CheckpointDto,
  RecentErrorDto,
  SupportBundleMetadataDto,
} from './dto/support-bundle.dto';
import { sanitizeErrorMessage } from '../common/utils/redaction.util';

@Injectable()
export class SupportBundleService {
  private readonly logger = new Logger(SupportBundleService.name);

  constructor(
    private readonly config: AppConfigService,
    private readonly registry: ContractRegistryService,
    private readonly indexerLag: IndexerLagService,
    private readonly checkpointRepo: IndexerCheckpointRepository,
    private readonly auditService: AuditService,
  ) {}

  async generateBundle(includeRequestIds = false): Promise<SupportBundleDto> {
    const startTime = Date.now();

    try {
      const [
        networkConfig,
        registrySnapshot,
        indexerStatus,
        checkpoints,
        recentErrors,
      ] = await Promise.all([
        this.getNetworkConfig(),
        this.getContractRegistrySnapshot(),
        this.getIndexerStatus(),
        this.getCheckpoints(),
        this.getRecentErrors(includeRequestIds),
      ]);

      const bundleJson = JSON.stringify({
        metadata: {} as SupportBundleMetadataDto,
        network_config: networkConfig,
        contract_registry: registrySnapshot,
        indexer_status: indexerStatus,
        checkpoints,
        recent_errors: recentErrors,
      });

      const bundleSize = Buffer.byteLength(bundleJson, 'utf8');
      const generatedAt = new Date().toISOString();

      const metadata: SupportBundleMetadataDto = {
        version: '1.0',
        generated_at: generatedAt,
        network: this.config.network,
        bundle_size_bytes: bundleSize,
      };

      const bundle: SupportBundleDto = {
        metadata,
        network_config: networkConfig,
        contract_registry: registrySnapshot,
        indexer_status: indexerStatus,
        checkpoints,
        recent_errors: recentErrors,
      };

      const duration = Date.now() - startTime;
      this.logger.log(
        `Generated support bundle in ${duration}ms (${bundleSize} bytes, ${recentErrors.length} errors, ${checkpoints.length} checkpoints)`,
      );

      return bundle;
    } catch (error) {
      this.logger.error(
        `Failed to generate support bundle: ${(error as Error).message}`,
        (error as Error).stack,
      );
      throw error;
    }
  }

  private async getNetworkConfig(): Promise<NetworkConfigDto> {
    return {
      network: this.config.network,
      network_passphrase: this.config.network === 'mainnet'
        ? 'Public Global Stellar Network ; September 2015'
        : 'Test SDF Network ; September 2015',
    };
  }

  private async getContractRegistrySnapshot(): Promise<ContractRegistrySnapshotDto> {
    try {
      const registry = await this.registry.getRegistry();
      const activeContracts = Object.entries(registry.data).map(([name, data]) => {
        const entry = data as Record<string, unknown>;
        return {
          name,
          contract_id: (entry.id as string) || '[REDACTED]',
          version: (entry.version as number) || 0,
          wasm_hash: ((entry.wasmHash as string) || '').substring(0, 16) + '...',
          updated_at: (entry.updatedAt as string) || new Date().toISOString(),
        };
      });

      return { active_contracts: activeContracts };
    } catch (error) {
      this.logger.warn(`Could not retrieve contract registry: ${(error as Error).message}`);
      return { active_contracts: [] };
    }
  }

  private async getIndexerStatus(): Promise<IndexerStatusDto> {
    try {
      const lagStatus = this.indexerLag.getStatus();
      let status = 'UNKNOWN';

      if (!lagStatus.isEnabled) {
        status = 'DISABLED';
      } else if (lagStatus.isLagging) {
        status = 'LAGGING';
      } else {
        status = 'HEALTHY';
      }

      return {
        current_network_ledger: lagStatus.currentNetworkLedger || 0,
        last_indexed_ledger: lagStatus.lastIndexedLedger || 0,
        lag_ledgers: lagStatus.lagLedgers || 0,
        is_lagging: lagStatus.isLagging || false,
        status,
      };
    } catch (error) {
      this.logger.warn(`Could not retrieve indexer status: ${(error as Error).message}`);
      return {
        current_network_ledger: 0,
        last_indexed_ledger: 0,
        lag_ledgers: 0,
        is_lagging: false,
        status: 'UNKNOWN',
      };
    }
  }

  private async getCheckpoints(): Promise<CheckpointDto[]> {
    try {
      const registry = await this.registry.getRegistry();
      const contracts = Object.keys(registry.data);

      const checkpoints: CheckpointDto[] = [];
      for (const contract of contracts) {
        // Try to extract contract ID from registry
        const registryEntry = registry.data[contract] as Record<string, unknown>;
        const contractId = registryEntry?.id as string | undefined;

        if (!contractId) continue;

        try {
          const lastLedger = await this.checkpointRepo.getLastLedger(contractId);
          if (lastLedger !== null) {
            checkpoints.push({
              contract_id: contractId,
              last_ledger: lastLedger,
              updated_at: new Date().toISOString(),
            });
          }
        } catch {
          // Continue on checkpoint error
        }
      }

      return checkpoints;
    } catch (error) {
      this.logger.warn(`Could not retrieve checkpoints: ${(error as Error).message}`);
      return [];
    }
  }

  private async getRecentErrors(includeRequestIds: boolean): Promise<RecentErrorDto[]> {
    try {
      // Fetch last 50 audit logs
      const result = await this.auditService.query({
        limit: 50,
        page: 1,
      });

      return result.data
        .map((log: AuditLog) => ({
          timestamp: log.createdAt instanceof Date ? log.createdAt.toISOString() : String(log.createdAt),
          action: log.action || 'unknown',
          actor: this.redactActor(log.actor),
          error_summary: this.extractErrorSummary(log.metadata),
          ...(includeRequestIds && log.requestId && { request_id: log.requestId }),
        }))
        .filter((entry) => entry.error_summary !== null)
        .slice(0, 50) as RecentErrorDto[];
    } catch (error) {
      this.logger.warn(`Could not retrieve recent errors: ${(error as Error).message}`);
      return [];
    }
  }

  private redactActor(actor: string | undefined): string {
    if (!actor) return '[UNKNOWN]';
    // Check if it looks like an email
    if (actor.includes('@')) {
      return '[REDACTED]';
    }
    // If it's a UUID or service name, it's safe
    return actor;
  }

  private extractErrorSummary(metadata: Record<string, unknown> | undefined): string | null {
    if (!metadata) return null;

    // Check for error field
    if (typeof metadata.error === 'string') {
      return sanitizeErrorMessage(metadata.error);
    }

    // Check for message field
    if (typeof metadata.message === 'string') {
      return sanitizeErrorMessage(metadata.message);
    }

    // Check for code field
    if (typeof metadata.code === 'string') {
      return metadata.code;
    }

    return null;
  }
}
