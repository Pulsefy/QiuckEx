import { Module } from "@nestjs/common";
import { AuthModule } from "../auth";
import { AuditModule } from "../audit/audit.module";
import { SupabaseModule } from "../supabase/supabase.module";
import { PrivacyAdminController } from "./privacy-admin.controller";
import { PrivacyController } from "./privacy.controller";
import { PrivacyRetentionScheduler } from "./privacy-retention.scheduler";
import { PrivacyRetentionService } from "./privacy-retention.service";
import { PrivacyService } from "./privacy.service";

@Module({
  imports: [AuditModule, AuthModule, SupabaseModule],
  controllers: [PrivacyController, PrivacyAdminController],
  providers: [PrivacyService, PrivacyRetentionService, PrivacyRetentionScheduler],
  exports: [PrivacyService, PrivacyRetentionService],
})
export class PrivacyModule {}
