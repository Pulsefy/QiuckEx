import { Module } from '@nestjs/common';
import { BranchPreviewController } from './branch-preview.controller';
import { BranchPreviewService } from './branch-preview.service';
import { BranchPreviewCache } from './branch-preview.cache';
import { BranchPreviewRepository } from './branch-preview.repository';
import { AuditModule } from '../audit/audit.module';
import { SupabaseModule } from '../supabase/supabase.module';

@Module({
  imports: [AuditModule, SupabaseModule],
  controllers: [BranchPreviewController],
  providers: [
    BranchPreviewService,
    BranchPreviewCache,
    BranchPreviewRepository,
  ],
  exports: [BranchPreviewService],
})
export class BranchPreviewModule {}