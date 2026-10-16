import {
  BadRequestException,
  ConflictException,
  Inject,
  Injectable,
  Logger,
  Optional,
} from '@nestjs/common';

import { SorobanErrorCode } from '../common/soroban-errors';
import {
  ClientContractAssertionDto,
  ContractCompatibilityFlow,
  ContractCompatibilityMetadataDto,
  ContractSchemaCompatibilityDto,
  FlowCompatibilityRequirementDto,
  ValidateWriteCompatibilityDto,
} from './dto';

export const CONTRACT_REGISTRY_READER = 'CONTRACT_REGISTRY_READER';
export const CONTRACT_CONFIG_READER = 'CONTRACT_CONFIG_READER';

export interface ContractRegistryReader {
  getRegistry(): Promise<{
    network?: string;
    etag?: string;
    data?: Record<string, unknown>;
  }>;
}

export interface ContractConfigReader {
  network?: string;
  quickexContractId?: string;
}

export const CONTRACT_VERSION_MISMATCH_CODE = SorobanErrorCode.VERSION_MISMATCH;
export const CONTRACT_SCHEMA_INCOMPATIBLE_CODE = SorobanErrorCode.SCHEMA_INCOMPATIBLE;
export const CONTRACT_DEPLOYMENT_OUTDATED_CODE = SorobanErrorCode.DEPLOYMENT_OUTDATED;
export const INVALID_CONTRACT_SCHEMA_VERSION_CODE = 'INVALID_CONTRACT_SCHEMA_VERSION';

const SEMVER_REGEX = /^\d+\.\d+\.\d+$/;

const DEFAULT_SUPPORTED_WRITE_METHODS: readonly string[] = [
  'deposit',
  'deposit_with_commitment',
  'deposit_partial',
  'withdraw',
  'refund',
  'dispute',
  'resolve_dispute',
  'resolve_dispute_multi_sig',
  'resolve_dispute_timeout',
  'toggle_privacy',
  'register_ephemeral_key',
  'stealth_withdraw',
  'health_check',
];

export const CONTRACT_FLOW_REQUIREMENTS: Record<
  ContractCompatibilityFlow,
  FlowCompatibilityRequirementDto
> = {
  link: {
    flow: 'link',
    contractName: 'quickex',
    minContractVersion: 1,
    maxContractVersion: 100_000,
    schemaCompatibility: { min: '1.0.0', max: '2.0.0' },
    supportedWriteMethods: [...DEFAULT_SUPPORTED_WRITE_METHODS],
  },
  quote: {
    flow: 'quote',
    contractName: 'quickex',
    minContractVersion: 1,
    maxContractVersion: 100_000,
    schemaCompatibility: { min: '1.0.0', max: '2.0.0' },
    supportedWriteMethods: [...DEFAULT_SUPPORTED_WRITE_METHODS],
  },
  pay_initiation: {
    flow: 'pay_initiation',
    contractName: 'quickex',
    minContractVersion: 1,
    maxContractVersion: 100_000,
    schemaCompatibility: { min: '1.0.0', max: '2.0.0' },
    supportedWriteMethods: [...DEFAULT_SUPPORTED_WRITE_METHODS],
  },
};

export function parseSemver(version: string): [number, number, number] | null {
  const trimmed = version?.trim();
  if (!trimmed || !SEMVER_REGEX.test(trimmed)) {
    return null;
  }
  const parts = trimmed.split('.').map((p) => Number.parseInt(p, 10));
  if (parts.length !== 3 || parts.some((n) => Number.isNaN(n) || n < 0)) {
    return null;
  }
  return [parts[0], parts[1], parts[2]];
}

export function compareSemver(a: string, b: string): number {
  const parsedA = parseSemver(a);
  const parsedB = parseSemver(b);
  if (!parsedA || !parsedB) {
    throw new BadRequestException({
      code: INVALID_CONTRACT_SCHEMA_VERSION_CODE,
      message: `Invalid semantic version format: "${!parsedA ? a : b}". Expected MAJOR.MINOR.PATCH (e.g. 1.0.0).`,
    });
  }

  for (let i = 0; i < 3; i += 1) {
    if (parsedA[i] > parsedB[i]) return 1;
    if (parsedA[i] < parsedB[i]) return -1;
  }
  return 0;
}

export function isSemverWithinWindow(
  version: string,
  window: ContractSchemaCompatibilityDto,
): boolean {
  return (
    compareSemver(version, window.min) >= 0 &&
    compareSemver(version, window.max) <= 0
  );
}

@Injectable()
export class ContractCompatibilityService {
  private readonly logger = new Logger(ContractCompatibilityService.name);

  constructor(
    @Optional()
    @Inject(CONTRACT_REGISTRY_READER)
    private readonly registryService?: ContractRegistryReader,
    @Optional()
    @Inject(CONTRACT_CONFIG_READER)
    private readonly configService?: ContractConfigReader,
  ) {}

  getFlowRequirements(
    flow: ContractCompatibilityFlow,
    contractName = 'quickex',
  ): FlowCompatibilityRequirementDto {
    const base = CONTRACT_FLOW_REQUIREMENTS[flow] ?? CONTRACT_FLOW_REQUIREMENTS.pay_initiation;
    return {
      ...base,
      contractName: contractName.trim().toLowerCase(),
      schemaCompatibility: { ...base.schemaCompatibility },
      supportedWriteMethods: [...base.supportedWriteMethods],
    };
  }

  async getCompatibilityMetadata(
    flow: ContractCompatibilityFlow = 'pay_initiation',
    contractName = 'quickex',
  ): Promise<ContractCompatibilityMetadataDto> {
    const normalizedName = contractName.trim().toLowerCase();
    const requirements = this.getFlowRequirements(flow, normalizedName);
    const resolved = await this.resolveActiveDeployment(normalizedName, requirements);
    return this.buildCompatibilityMetadata(flow, normalizedName, requirements, resolved);
  }

  private buildCompatibilityMetadata(
    flow: ContractCompatibilityFlow,
    normalizedName: string,
    requirements: FlowCompatibilityRequirementDto,
    resolved: {
      network: string;
      contractId: string;
      previousContractId?: string;
      effectiveLedger?: number;
      effectiveTime?: string;
      wasmHash: string;
      contractVersion: number;
      schemaVersion: string;
      schemaCompatibility: ContractSchemaCompatibilityDto;
      hasExplicitRegistryRecord: boolean;
    },
    currentLedger?: number,
  ): ContractCompatibilityMetadataDto {
    const effectiveWindow = this.intersectCompatibilityWindows(
      requirements.schemaCompatibility,
      resolved.schemaCompatibility,
    );

    const compatible =
      resolved.contractVersion >= requirements.minContractVersion &&
      resolved.contractVersion <= requirements.maxContractVersion &&
      isSemverWithinWindow(resolved.schemaVersion, effectiveWindow);

    const transitionActive = this.isTransitionWindowActive(resolved, currentLedger);

    return {
      contractName: normalizedName,
      network: resolved.network,
      contractId: resolved.contractId,
      wasmHash: resolved.wasmHash,
      contractVersion: resolved.contractVersion,
      schemaVersion: resolved.schemaVersion,
      schemaCompatibility: effectiveWindow,
      flow,
      requirements,
      compatible,
      transition:
        resolved.previousContractId || resolved.effectiveLedger || resolved.effectiveTime
          ? {
              active: transitionActive,
              previousContractId: resolved.previousContractId,
              effectiveLedger: resolved.effectiveLedger,
              effectiveTime: resolved.effectiveTime,
            }
          : { active: false },
    };
  }

  async validateWriteCompatibility(
    input: ValidateWriteCompatibilityDto,
    currentLedger?: number,
  ): Promise<ContractCompatibilityMetadataDto> {
    const flow: ContractCompatibilityFlow = input.flow ?? 'pay_initiation';
    const contractName = (input.contractName ?? 'quickex').trim().toLowerCase();
    const requirements = this.getFlowRequirements(flow, contractName);
    const resolved = await this.resolveActiveDeployment(contractName, requirements);
    const metadata = this.buildCompatibilityMetadata(
      flow,
      contractName,
      requirements,
      resolved,
      currentLedger,
    );

    const clientContractId =
      input.assertion?.contractId?.trim() || input.contractId?.trim();
    const clientContractVersion =
      input.assertion?.contractVersion ?? input.contractVersion;
    const clientSchemaVersion =
      input.assertion?.schemaVersion?.trim() || input.schemaVersion?.trim();

    // 1. Validate schema version format if provided
    if (clientSchemaVersion && !parseSemver(clientSchemaVersion)) {
      throw new BadRequestException({
        code: INVALID_CONTRACT_SCHEMA_VERSION_CODE,
        message: `Client schema version "${clientSchemaVersion}" is malformed. Expected semantic version (e.g. "1.0.0").`,
        details: {
          clientSchemaVersion,
          expectedFormat: 'MAJOR.MINOR.PATCH',
          contractCompatibility: metadata,
        },
      });
    }

    // 2. Check target contract deployment ID and transition window
    if (
      clientContractId &&
      resolved.contractId &&
      clientContractId !== resolved.contractId
    ) {
      const isPreviousContract =
        Boolean(resolved.previousContractId) &&
        clientContractId === resolved.previousContractId;

      if (isPreviousContract) {
        const withinWindow = this.isTransitionWindowActive(resolved, currentLedger);
        if (!withinWindow) {
          throw new ConflictException({
            code: CONTRACT_DEPLOYMENT_OUTDATED_CODE,
            message: `Contract deployment "${clientContractId}" transition window has expired. Please refresh contract registry to target active contract "${resolved.contractId}".`,
            details: {
              reason: 'TRANSITION_WINDOW_EXPIRED',
              requestedContractId: clientContractId,
              activeContractId: resolved.contractId,
              previousContractId: resolved.previousContractId,
              effectiveLedger: resolved.effectiveLedger ?? null,
              effectiveTime: resolved.effectiveTime ?? null,
              activeContractVersion: resolved.contractVersion,
              activeSchemaVersion: resolved.schemaVersion,
              schemaCompatibility: metadata.schemaCompatibility,
              action: 'REFRESH_CONTRACT_REGISTRY',
              contractCompatibility: metadata,
            },
          });
        }
      } else if (resolved.hasExplicitRegistryRecord) {
        throw new ConflictException({
          code: CONTRACT_DEPLOYMENT_OUTDATED_CODE,
          message: `Contract deployment "${clientContractId}" does not match active contract "${resolved.contractId}" (version ${resolved.contractVersion}). Refresh contract registry before submitting writes.`,
          details: {
            reason: 'CONTRACT_ID_MISMATCH',
            requestedContractId: clientContractId,
            activeContractId: resolved.contractId,
            activeContractVersion: resolved.contractVersion,
            activeSchemaVersion: resolved.schemaVersion,
            schemaCompatibility: metadata.schemaCompatibility,
            action: 'REFRESH_CONTRACT_REGISTRY',
            contractCompatibility: metadata,
          },
        });
      }
    }

    // 3. Check client contract version assertion against active contract version and flow bounds
    if (clientContractVersion !== undefined && clientContractVersion !== null) {
      if (
        clientContractVersion < metadata.requirements.minContractVersion ||
        clientContractVersion > metadata.requirements.maxContractVersion
      ) {
        throw new ConflictException({
          code: CONTRACT_VERSION_MISMATCH_CODE,
          message: `Contract version ${clientContractVersion} is outside the supported range [${metadata.requirements.minContractVersion}, ${metadata.requirements.maxContractVersion}] for flow "${flow}".`,
          details: {
            reason: 'FLOW_VERSION_UNSUPPORTED',
            flow,
            clientContractVersion,
            activeContractVersion: resolved.contractVersion,
            minContractVersion: metadata.requirements.minContractVersion,
            maxContractVersion: metadata.requirements.maxContractVersion,
            activeContractId: resolved.contractId,
            activeSchemaVersion: resolved.schemaVersion,
            schemaCompatibility: metadata.schemaCompatibility,
            action: 'UPGRADE_CLIENT_OR_REFRESH_REGISTRY',
            contractCompatibility: metadata,
          },
        });
      }

      if (clientContractVersion !== resolved.contractVersion) {
        const isTransitionGraceAllowed =
          Boolean(resolved.previousContractId) &&
          this.isTransitionWindowActive(resolved, currentLedger) &&
          clientContractId === resolved.previousContractId &&
          clientContractVersion === resolved.contractVersion - 1;

        if (!isTransitionGraceAllowed) {
          throw new ConflictException({
            code: CONTRACT_VERSION_MISMATCH_CODE,
            message: `Client expects contract version ${clientContractVersion}, but active deployment for "${contractName}" is at version ${resolved.contractVersion}.`,
            details: {
              reason:
                clientContractVersion < resolved.contractVersion
                  ? 'CLIENT_CONTRACT_VERSION_OUTDATED'
                  : 'CLIENT_CONTRACT_VERSION_AHEAD',
              flow,
              clientContractVersion,
              activeContractVersion: resolved.contractVersion,
              activeContractId: resolved.contractId,
              activeSchemaVersion: resolved.schemaVersion,
              schemaCompatibility: metadata.schemaCompatibility,
              action: 'REFRESH_CONTRACT_REGISTRY',
              contractCompatibility: metadata,
            },
          });
        }
      }
    }

    // 4. Check client schema version compatibility window
    if (clientSchemaVersion) {
      if (!isSemverWithinWindow(clientSchemaVersion, metadata.schemaCompatibility)) {
        const cmpMin = compareSemver(
          clientSchemaVersion,
          metadata.schemaCompatibility.min,
        );
        throw new ConflictException({
          code: CONTRACT_SCHEMA_INCOMPATIBLE_CODE,
          message: `Client contract schema version "${clientSchemaVersion}" is incompatible with active "${contractName}" deployment schema window [${metadata.schemaCompatibility.min} - ${metadata.schemaCompatibility.max}] (active schema: ${resolved.schemaVersion}).`,
          details: {
            reason:
              cmpMin < 0 ? 'CLIENT_SCHEMA_TOO_OLD' : 'CLIENT_SCHEMA_TOO_NEW',
            flow,
            clientSchemaVersion,
            activeSchemaVersion: resolved.schemaVersion,
            schemaCompatibility: metadata.schemaCompatibility,
            activeContractVersion: resolved.contractVersion,
            activeContractId: resolved.contractId,
            action: cmpMin < 0 ? 'UPGRADE_CLIENT' : 'REFRESH_CONTRACT_REGISTRY',
            contractCompatibility: metadata,
          },
        });
      }
    }

    // 5. Verify active deployment itself satisfies flow requirements
    if (!metadata.compatible) {
      throw new ConflictException({
        code: CONTRACT_SCHEMA_INCOMPATIBLE_CODE,
        message: `Active contract deployment "${contractName}" (version ${resolved.contractVersion}, schema ${resolved.schemaVersion}) does not satisfy compatibility requirements for flow "${flow}".`,
        details: {
          reason: 'ACTIVE_DEPLOYMENT_INCOMPATIBLE_WITH_FLOW',
          flow,
          activeContractVersion: resolved.contractVersion,
          activeSchemaVersion: resolved.schemaVersion,
          schemaCompatibility: metadata.schemaCompatibility,
          requirements: metadata.requirements,
          action: 'CONTACT_OPERATOR_OR_ROLLBACK',
          contractCompatibility: metadata,
        },
      });
    }

    return metadata;
  }

  extractClientAssertionFromHeaders(
    headers: Record<string, string | string[] | undefined>,
  ): ClientContractAssertionDto {
    const readHeader = (name: string): string | undefined => {
      const value = headers[name] ?? headers[name.toLowerCase()];
      if (Array.isArray(value)) return value[0]?.trim();
      return typeof value === 'string' ? value.trim() : undefined;
    };

    const rawVersion = readHeader('x-contract-version');
    const rawSchema = readHeader('x-contract-schema-version');
    const rawContractId = readHeader('x-contract-id');

    let contractVersion: number | undefined;
    if (rawVersion !== undefined && rawVersion !== '') {
      const parsed = Number.parseInt(rawVersion, 10);
      if (Number.isNaN(parsed) || parsed < 1 || String(parsed) !== rawVersion) {
        throw new BadRequestException({
          code: CONTRACT_VERSION_MISMATCH_CODE,
          message: `Invalid X-Contract-Version header "${rawVersion}". Must be a positive integer.`,
        });
      }
      contractVersion = parsed;
    }

    return {
      contractVersion,
      schemaVersion: rawSchema || undefined,
      contractId: rawContractId || undefined,
    };
  }

  private isTransitionWindowActive(
    deployment: {
      previousContractId?: string;
      effectiveLedger?: number;
      effectiveTime?: string;
    },
    currentLedger?: number,
  ): boolean {
    if (!deployment.previousContractId) {
      return false;
    }

    if (deployment.effectiveTime) {
      const effectiveTimestamp = Date.parse(deployment.effectiveTime);
      if (!Number.isNaN(effectiveTimestamp) && Date.now() >= effectiveTimestamp) {
        return false;
      }
    }

    if (
      deployment.effectiveLedger !== undefined &&
      currentLedger !== undefined &&
      currentLedger >= deployment.effectiveLedger
    ) {
      return false;
    }

    return true;
  }

  private intersectCompatibilityWindows(
    flowWindow: ContractSchemaCompatibilityDto,
    deploymentWindow: ContractSchemaCompatibilityDto,
  ): ContractSchemaCompatibilityDto {
    try {
      const min =
        compareSemver(flowWindow.min, deploymentWindow.min) >= 0
          ? flowWindow.min
          : deploymentWindow.min;
      const max =
        compareSemver(flowWindow.max, deploymentWindow.max) <= 0
          ? flowWindow.max
          : deploymentWindow.max;
      return { min, max };
    } catch {
      return deploymentWindow;
    }
  }

  private async resolveActiveDeployment(
    contractName: string,
    requirements: FlowCompatibilityRequirementDto,
  ): Promise<{
    network: string;
    contractId: string;
    previousContractId?: string;
    effectiveLedger?: number;
    effectiveTime?: string;
    wasmHash: string;
    contractVersion: number;
    schemaVersion: string;
    schemaCompatibility: ContractSchemaCompatibilityDto;
    hasExplicitRegistryRecord: boolean;
  }> {
    const defaultNetwork = this.configService?.network ?? 'testnet';
    const configuredContractId =
      this.configService?.quickexContractId?.trim() ||
      process.env.QUICKEX_CONTRACT_ID?.trim() ||
      '';

    if (this.registryService) {
      try {
        const registry = await this.registryService.getRegistry();
        const entry = registry.data?.[contractName] as
          | Record<string, unknown>
          | undefined;
        if (entry && typeof entry === 'object') {
          const rawCompat = entry.schemaCompatibility as
            | { min?: string; max?: string }
            | undefined;
          return {
            network: registry.network || defaultNetwork,
            contractId: String(entry.id ?? configuredContractId),
            previousContractId: entry.previousContractId
              ? String(entry.previousContractId)
              : undefined,
            effectiveLedger:
              typeof entry.effectiveLedger === 'number'
                ? entry.effectiveLedger
                : undefined,
            effectiveTime: entry.effectiveTime
              ? String(entry.effectiveTime)
              : undefined,
            wasmHash: String(entry.wasmHash ?? ''),
            contractVersion: Number(entry.version ?? 1),
            schemaVersion: String(entry.schemaVersion ?? '1.0.0'),
            schemaCompatibility: {
              min: rawCompat?.min ?? requirements.schemaCompatibility.min,
              max: rawCompat?.max ?? requirements.schemaCompatibility.max,
            },
            hasExplicitRegistryRecord: true,
          };
        }
      } catch (err) {
        this.logger.debug(
          `Registry lookup for ${contractName} fell back to defaults: ${(err as Error).message}`,
        );
      }
    }

    return {
      network: defaultNetwork,
      contractId: configuredContractId,
      wasmHash: '',
      contractVersion: 1,
      schemaVersion: '1.0.0',
      schemaCompatibility: { ...requirements.schemaCompatibility },
      hasExplicitRegistryRecord: false,
    };
  }
}
