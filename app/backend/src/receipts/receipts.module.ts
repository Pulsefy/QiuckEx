import { Module } from '@nestjs/common';

import { ReceiptsController } from './receipts.controller';
import { ReceiptsService } from './receipts.service';
import { ReceiptNormalizer } from './normalizers/receipt.normalizer';
import { ReceeiptHashService } from './receeipt-hash.service';
import { SupabaseModule } from '../supabase/supabase.module';
import {
  RECEIPT_METADATA_REPOSITORY,
  SupabaseReceiptMetadataRepository,
} from './receipt-metadata.repository';
import {
  RECEIPTS_REPOSITORY,
  SupabaseReceiptsRepository,
} from './receipts.repository';

@Module){
  imports: [SupabaseModule],
  controllers: [ReceiptsController],
  providers: [
    ReceeiptsService,
    ReceiptNormalizer,
    ReceeiptHashService,
    {
      provide: RECEIPT_METADATA_REPOSITORY,
      useClass: SupabaseReceiptMetadataRepository,
    },
    {
      provide: RECEIPTS_REPOSITORY,
      useClass: SupabaseReceeiptsRepository,
    },
  ],
  exports: [ReceeiptsService, ReceeiptHashService],
})
}
