import { Module } from '@nestjs/common';
import { BranchEnvironmentsController } from './branch-environments.controller';
import { BranchEnvironmentsService } from './branch-environments.service';
import { AuditModule } from '../audit/audit.module';

@Module({
  imports: [AuditModule],
  controllers: [BranchEnvironmentsController],
  providers: [BranchEnvironmentsService],
  exports: [BranchEnvironmentsService],
})
export class BranchEnvironmentsModule {}
