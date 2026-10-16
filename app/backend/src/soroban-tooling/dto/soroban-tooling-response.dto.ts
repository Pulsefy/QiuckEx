import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class FundingPreflightResponseDto {
  @ApiProperty({ description: 'Whether the account satisfies minimum balance requirements', example: true })
  ready: boolean;

  @ApiProperty({ description: 'Whether the account exists on the network', example: true })
  accountExists: boolean;

  @ApiProperty({ description: 'Minimum balance in XLM required', example: 5 })
  minimumBalanceXlm: number;

  @ApiProperty({ description: 'Current balance in XLM', example: '100.5' })
  currentBalanceXlm: string;

  @ApiProperty({ description: 'Target network name', example: 'testnet' })
  network: string;

  @ApiProperty({ description: 'Faucet URL for funding', example: 'https://laboratory.stellar.org/...' })
  faucetUrl: string;

  @ApiProperty({ description: 'Remediation steps if unready', type: [String], example: [] })
  remediation: string[];
}

export class ContractActionPlanDto {
  @ApiProperty({ description: 'Action step name', example: 'install' })
  step: string;

  @ApiProperty({ description: 'Whether action is skipped', example: false })
  skipped: boolean;

  @ApiPropertyOptional({ description: 'Reason for skipping action', example: 'same wasm hash already active' })
  reason?: string;
}

export class PlannedContractDto {
  @ApiProperty({ description: 'Contract name', example: 'quickex' })
  name: string;

  @ApiProperty({ description: 'Resolved wasm path', example: '/path/to/quickex.wasm' })
  wasmPath: string;

  @ApiProperty({ description: 'Whether wasm file exists on disk', example: true })
  wasmExists: boolean;

  @ApiPropertyOptional({ description: 'SHA-256 hash of the wasm file', nullable: true, example: 'abc123...' })
  wasmHash: string | null;

  @ApiProperty({ description: 'Initialization method name', example: 'initialize' })
  initMethod: string;

  @ApiProperty({ description: 'Initialization arguments', type: [String], example: [] })
  initArgs: string[];

  @ApiProperty({ description: 'Planned actions for contract', type: [ContractActionPlanDto] })
  actions: ContractActionPlanDto[];
}

export class DeploymentPlanResponseDto {
  @ApiProperty({ description: 'Network identifier', example: 'testnet' })
  network: string;

  @ApiProperty({ description: 'Whether plan is a dry run', example: true })
  dryRun: boolean;

  @ApiProperty({ description: 'Whether registry will be published', example: true })
  publishRegistry: boolean;

  @ApiProperty({ description: 'Stellar network passphrase', example: 'Test SDF Network ; September 2015' })
  networkPassphrase: string;

  @ApiPropertyOptional({ description: 'Funding check status or null', type: FundingPreflightResponseDto, nullable: true })
  funding: FundingPreflightResponseDto | null;

  @ApiProperty({ description: 'CLI commands to execute deployment', type: [String], example: ['soroban contract install ...'] })
  commands: string[];

  @ApiProperty({ description: 'List of planned contracts', type: [PlannedContractDto] })
  contracts: PlannedContractDto[];

  @ApiProperty({ description: 'Whether plan is ready for deployment', example: true })
  ready: boolean;
}
