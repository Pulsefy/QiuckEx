import { Module } from '@nestjs/common';
import { ApiKeysModule } from '../api-keys/api-keys.module';
import { ApiKeyGuard } from '../auth/guards/api-key.guard';
import { SupabaseModule } from '../supabase/supabase.module';
import { DemoController } from './demo.controller';
import { DemoService } from './demo.service';

@Module({
  imports: [ApiKeysModule, SupabaseModule],
  controllers: [DemoController],
  providers: [DemoService, ApiKeyGuard],
  exports: [DemoService],
})
export class DemoModule {}