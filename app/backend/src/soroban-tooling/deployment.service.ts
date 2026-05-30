import { createHash } from 'crypto';
import { Injectable } from '@nestjs/common';
import { existsSync, readFileSync } from 'fs';
import * as path from 'path';

import { AppConfigService } from '../config';
import { ContractRegistryService } from '../contracts/contract-registry.service';
import { DeploymentPlanDto } from './dto/testnet-tooling.dto';
import { FundingHelperService } from './funding-helper.service';

@Injectable()
export class DeploymentService {
  constructor(
    private readonly configService: AppConfigService,
    private readonly fundingHelperService: FundingHelperService,
    private readonly contractRegistryService: ContractRegistryService,
  ) {}

  async planDeployment(dto: DeploymentPlanDto) {
    const dryRun = dto.dryRun ?? true;
    const publishRegistry = dto.publishRegistry ?? true;
    const funding = dto.adminPublicKey
      ? await this.fundingHelperService.checkFunding({
          accountId: dto.adminPublicKey,
          minBalanceXlm: 5,
        })
      : null;

    const registry = await this.contractRegistryService.getRegistry();
    const plannedContracts = dto.contracts.map((contract) => {
      const absoluteWasmPath = path.resolve(contract.wasmPath);
      const exists = existsSync(absoluteWasmPath);
      const wasmHash = exists
        ? createHash('sha256').update(readFileSync(absoluteWasmPath)).digest('hex')
        : null;
      const currentRegistry = registry.data[contract.name] as
        | { id?: string; wasmHash?: string; version?: number }
        | undefined;
      const alreadyInstalled = Boolean(currentRegistry?.wasmHash && currentRegistry.wasmHash === wasmHash);
      const alreadyDeployed = Boolean(currentRegistry?.id && alreadyInstalled);

      return {
        name: contract.name,
        wasmPath: absoluteWasmPath,
        wasmExists: exists,
        wasmHash,
        initMethod: contract.initMethod ?? 'initialize',
        initArgs: contract.initArgs ?? (dto.adminPublicKey ? [dto.adminPublicKey] : []),
        actions: [
          { step: 'install', skipped: alreadyInstalled, reason: alreadyInstalled ? 'same wasm hash already active in registry' : undefined },
          { step: 'deploy', skipped: alreadyDeployed, reason: alreadyDeployed ? 'same contract already active in registry' : undefined },
          {
            step: 'initialize',
            skipped: alreadyDeployed && (contract.initMethod ?? 'initialize') === 'initialize',
            reason:
              alreadyDeployed && (contract.initMethod ?? 'initialize') === 'initialize'
                ? 'active registry entry implies contract was already initialized'
                : undefined,
          },
        ],
      };
    });

    return {
      network: dto.network,
      dryRun,
      publishRegistry,
      networkPassphrase:
        dto.network === 'mainnet'
          ? 'Public Global Stellar Network ; September 2015'
          : 'Test SDF Network ; September 2015',
      funding,
      commands: plannedContracts.flatMap((contract) => {
        const commands: string[] = [];
        commands.push(`soroban contract install --network ${dto.network} --source ${dto.source} --wasm ${contract.wasmPath}`);
        commands.push(`soroban contract deploy --network ${dto.network} --source ${dto.source} --wasm-hash ${contract.wasmHash ?? '<missing-wasm>'}`);
        if (contract.initMethod) {
          commands.push(
            `soroban contract invoke --network ${dto.network} --source ${dto.source} --id <contract-id> -- ${contract.initMethod} ${contract.initArgs.join(' ')}`.trim(),
          );
        }
        return commands;
      }),
      contracts: plannedContracts,
      ready:
        plannedContracts.every((contract) => contract.wasmExists) &&
        (!funding || funding.ready || dryRun),
    };
  }
}
