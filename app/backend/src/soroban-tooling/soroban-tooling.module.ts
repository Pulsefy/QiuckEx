import { Module } from '@nestjs/common';

import { ApiKeysModule } from '../api-keys/api-keys.module';

import { ContractsModule } from '../contracts/contracts.module';
import { StellarModule } from '../stellar/stellar.module';
import { DeploymentService } from './deployment.service';
import { FundingHelperService } from './funding-helper.service';
import { SorobanToolingController } from './soroban-tooling.controller';

@Module({
  imports: [ApiKeysModule, StellarModule, ContractsModule],
  controllers: [SorobanToolingController],
  providers: [FundingHelperService, DeploymentService, ],
  exports: [FundingHelperService, DeploymentService],
})
export class SorobanToolingModule {}
