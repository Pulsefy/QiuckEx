import { Module } from '@nestjs/common';
import { SupabaseModule } from '../supabase/supabase.module';
import { PreviewScopeService } from './preview-scope.service';
import { PreviewScopeGuard } from './preview-scope.guard';

@Module({
  imports: [SupabaseModule],
  providers: [PreviewScopeService, PreviewScopeGuard],
  exports: [PreviewScopeService, PreviewScopeGuard],
})
export class PreviewScopeModule {}
