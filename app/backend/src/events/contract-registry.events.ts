export const ContractRegistryPublishedEvent =
  'contract_registry.published';
export const ContractRegistryRolledBackEvent =
  'contract_registry.rolled_back';

export class ContractRegistryPublishedEventPayload {
  constructor(
    public readonly version: number,
    public readonly contracts: {
      name: string;
      contractId: string;
      wasmHash: string;
      contractVersion: number;
      deploymentId?: string;
    }[],
    public readonly actor: string,
  ) {}
}

export class ContractRegistryRolledBackEventPayload {
  constructor(
    public readonly contractName: string,
    public readonly registryVersion: number,
    public readonly contractId: string,
    public readonly wasmHash: string,
    public readonly contractVersion: number,
    public readonly actor: string,
  ) {}
}
