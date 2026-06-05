import {
  Injectable,
  Logger,
  Inject,
} from '@nestjs/common';
import { ContractRegistryService } from './contract-registry.service';
import {
  ContractCompatibilityMetadata,
  ContractCompatibilityStatus,
  ContractVersionRequirement,
  ClientContractRequirements,
} from './dto/contract-compatibility.dto';
import { ContractCompatibilityError, ContractCompatibilityErrorCode } from './errors/contract-compatibility.errors';

/**
 * Configuration for endpoint-specific contract version requirements.
 * Each endpoint can define minimum version requirements for contracts it depends on.
 */
export interface EndpointContractRequirements {
  /** Endpoint path pattern (e.g., 'links/metadata', 'payment-links/status') */
  endpoint: string;
  /** HTTP method */
  method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
  /** Required contract versions for this endpoint */
  requirements: ContractVersionRequirement[];
  /** Whether to reject requests from incompatible clients */
  rejectIncompatible: boolean;
  /** Whether to include compatibility metadata in response */
  includeMetadata: boolean;
}

/**
 * Default endpoint requirements configuration.
 * These define what contract versions are needed for each flow.
 */
const DEFAULT_ENDPOINT_REQUIREMENTS: EndpointContractRequirements[] = [
  {
    endpoint: 'links/metadata',
    method: 'POST',
    requirements: [
      { name: 'quickex', minVersion: 1 },
    ],
    rejectIncompatible: false,
    includeMetadata: true,
  },
  {
    endpoint: 'payment-links/status',
    method: 'GET',
    requirements: [
      { name: 'quickex', minVersion: 1 },
    ],
    rejectIncompatible: false,
    includeMetadata: true,
  },
  {
    endpoint: 'payments/initiate',
    method: 'POST',
    requirements: [
      { name: 'quickex', minVersion: 2 },
    ],
    rejectIncompatible: true,
    includeMetadata: true,
  },
  {
    endpoint: 'quotes',
    method: 'POST',
    requirements: [
      { name: 'quickex', minVersion: 1 },
    ],
    rejectIncompatible: false,
    includeMetadata: true,
  },
];

@Injectable()
export class ContractCompatibilityService {
  private readonly logger = new Logger(ContractCompatibilityService.name);
  private readonly endpointRequirements: Map<string, EndpointContractRequirements>;
  private readonly deprecationDeadline: string;
  private readonly upgradeGuideUrl: string;

  constructor(
    @Inject('ContractRegistryService')
    private readonly contractRegistryService: ContractRegistryService,
  ) {
    // Index requirements by endpoint+method key
    this.endpointRequirements = new Map();
    for (const req of DEFAULT_ENDPOINT_REQUIREMENTS) {
      const key = this.buildEndpointKey(req.endpoint, req.method);
      this.endpointRequirements.set(key, req);
    }

    // Deprecation deadline - 30 days from now by default
    const deadline = new Date();
    deadline.setDate(deadline.getDate() + 30);
    this.deprecationDeadline = deadline.toISOString();

    this.upgradeGuideUrl = process.env.CONTRACT_UPGRADE_GUIDE_URL || 
      'https://docs.quickex.io/contract-upgrade-guide';
  }

  /**
   * Build a cache key for endpoint+method.
   */
  private buildEndpointKey(endpoint: string, method: string): string {
    return `${method.toUpperCase()}:${endpoint.toLowerCase()}`;
  }

  /**
   * Get the contract requirements for a specific endpoint.
   */
  getEndpointRequirements(endpoint: string, method: string): EndpointContractRequirements | undefined {
    const key = this.buildEndpointKey(endpoint, method);
    return this.endpointRequirements.get(key);
  }

  /**
   * Register or update endpoint requirements.
   */
  registerEndpointRequirements(requirements: EndpointContractRequirements): void {
    const key = this.buildEndpointKey(requirements.endpoint, requirements.method);
    this.endpointRequirements.set(key, requirements);
    this.logger.debug(`Registered contract requirements for ${key}`);
  }

  /**
   * Check if client contract requirements are compatible with deployed contracts.
   * This is called when a client provides their supported versions via header or body.
   */
  async checkClientCompatibility(
    clientRequirements: ClientContractRequirements,
  ): Promise<ContractCompatibilityMetadata> {
    const registry = await this.contractRegistryService.getRegistry();
    const contractStatuses: ContractCompatibilityStatus[] = [];
    let allCompatible = true;
    let anyDeprecated = false;

    for (const req of clientRequirements.requirements) {
      const deployedContract = registry.data[req.name];
      
      if (!deployedContract) {
        // Contract not found in registry
        contractStatuses.push({
          name: req.name,
          deployedVersion: 0,
          requiredMinVersion: req.minVersion,
          compatible: false,
          incompatibilityReason: 'CONTRACT_NOT_FOUND',
        });
        allCompatible = false;
        continue;
      }

      const deployedVersion = deployedContract.version as number;
      const isCompatible = deployedVersion >= req.minVersion && 
        (!req.maxVersion || deployedVersion <= req.maxVersion);
      
      const isDeprecated = req.deprecatedVersions?.includes(deployedVersion.toString()) ?? false;

      if (!isCompatible) {
        allCompatible = false;
      }
      if (isDeprecated) {
        anyDeprecated = true;
      }

      contractStatuses.push({
        name: req.name,
        deployedVersion,
        requiredMinVersion: req.minVersion,
        compatible: isCompatible,
        deprecated: isDeprecated,
        deprecationMessage: isDeprecated 
          ? `Contract version ${deployedVersion} is deprecated. Please upgrade your client.`
          : undefined,
        incompatibilityReason: !isCompatible
          ? this.getIncompatibilityReason(deployedVersion, req)
          : undefined,
      });
    }

    return {
      compatible: allCompatible,
      registryVersion: registry.version,
      contracts: contractStatuses,
      deprecationDeadline: anyDeprecated ? this.deprecationDeadline : undefined,
      upgradeGuideUrl: this.upgradeGuideUrl,
    };
  }

  /**
   * Get compatibility metadata for an endpoint based on default requirements.
   * Used to include compatibility info in response payloads.
   */
  async getEndpointCompatibilityMetadata(
    endpoint: string,
    method: string,
  ): Promise<ContractCompatibilityMetadata | null> {
    const requirements = this.getEndpointRequirements(endpoint, method);
    if (!requirements || !requirements.includeMetadata) {
      return null;
    }

    const registry = await this.contractRegistryService.getRegistry();
    const contractStatuses: ContractCompatibilityStatus[] = [];
    let allCompatible = true;

    for (const req of requirements.requirements) {
      const deployedContract = registry.data[req.name];
      
      if (!deployedContract) {
        contractStatuses.push({
          name: req.name,
          deployedVersion: 0,
          requiredMinVersion: req.minVersion,
          compatible: false,
          incompatibilityReason: 'CONTRACT_NOT_DEPLOYED',
        });
        allCompatible = false;
        continue;
      }

      const deployedVersion = deployedContract.version as number;
      const isCompatible = deployedVersion >= req.minVersion && 
        (!req.maxVersion || deployedVersion <= req.maxVersion);

      if (!isCompatible) {
        allCompatible = false;
      }

      contractStatuses.push({
        name: req.name,
        deployedVersion,
        requiredMinVersion: req.minVersion,
        compatible: isCompatible,
        incompatibilityReason: !isCompatible
          ? this.getIncompatibilityReason(deployedVersion, req)
          : undefined,
      });
    }

    return {
      compatible: allCompatible,
      registryVersion: registry.version,
      contracts: contractStatuses,
      deprecationDeadline: anyDeprecated ? this.deprecationDeadline : undefined,
      upgradeGuideUrl: this.upgradeGuideUrl,
    };
  }

  /**
   * Validate that a request is compatible with contract requirements.
   * Throws ContractCompatibilityError if the client's contract version is unsupported.
   */
  async validateRequestCompatibility(
    endpoint: string,
    method: string,
    clientRequirements?: ClientContractRequirements,
  ): Promise<{ compatible: boolean; metadata?: ContractCompatibilityMetadata }> {
    const requirements = this.getEndpointRequirements(endpoint, method);
    
    // If no requirements defined for this endpoint, allow the request
    if (!requirements) {
      return { compatible: true };
    }

    // If client provided their requirements, check compatibility
    if (clientRequirements) {
      const metadata = await this.checkClientCompatibility(clientRequirements);
      if (!metadata.compatible && requirements.rejectIncompatible) {
        throw new ContractCompatibilityError(
          ContractCompatibilityErrorCode.CONTRACT_VERSION_UNSUPPORTED,
          'Client contract version is not supported by this endpoint',
          metadata,
        );
      }
      return { compatible: metadata.compatible, metadata };
    }

    // Check against default requirements
    const metadata = await this.getEndpointCompatibilityMetadata(endpoint, method);
    if (metadata && !metadata.compatible && requirements.rejectIncompatible) {
      throw new ContractCompatibilityError(
        ContractCompatibilityErrorCode.CONTRACT_VERSION_UNSUPPORTED,
        'Server contract version is incompatible with endpoint requirements',
        metadata,
      );
    }

    return { compatible: true, metadata: metadata || undefined };
  }

  /**
   * Determine the specific reason for incompatibility.
   */
  private getIncompatibilityReason(
    deployedVersion: number,
    requirement: ContractVersionRequirement,
  ): string {
    if (deployedVersion < requirement.minVersion) {
      return 'CONTRACT_VERSION_TOO_LOW';
    }
    if (requirement.maxVersion && deployedVersion > requirement.maxVersion) {
      return 'CONTRACT_VERSION_TOO_HIGH';
    }
    return 'CONTRACT_VERSION_MISMATCH';
  }

  /**
   * Parse client contract requirements from request headers.
   * Looks for X-Contract-Requirements header with JSON payload.
   */
  parseClientRequirementsFromHeader(headerValue?: string): ClientContractRequirements | undefined {
    if (!headerValue) {
      return undefined;
    }

    try {
      const parsed = JSON.parse(headerValue);
      if (!parsed.requirements || !Array.isArray(parsed.requirements)) {
        this.logger.warn('Invalid contract requirements header format');
        return undefined;
      }
      return parsed as ClientContractRequirements;
    } catch (error) {
      this.logger.warn(`Failed to parse contract requirements header: ${(error as Error).message}`);
      return undefined;
    }
  }

  /**
   * Get all registered endpoint requirements (for debugging/admin purposes).
   */
  getAllEndpointRequirements(): EndpointContractRequirements[] {
    return Array.from(this.endpointRequirements.values());
  }
}