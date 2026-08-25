/**
 * ReceiptsModule
 *
 * Location: app/backend/src/receipts/receipts.module.ts
 */

import { Module } from "@nestjs/common";
import { ReceiptsController } from "./receipts.controller";
import { ReceiptsService } from "./receipts.service";
import { ReceiptNormalizer } from "./normalizers/receipt.normalizer";
import { ReceiptHashService } from "./receipt-hash.service";
import { SupabaseModule } from "../supabase/supabase.module";
import {
  RECEIPT_METADATA_REPOSITORY,
  SupabaseReceiptMetadataRepository,
} from "./receipt-metadata.repository";

@Module({
  imports: [SupabaseModule],
  controllers: [ReceiptsController],
  providers: [
    ReceiptsService,
    ReceiptNormalizer,
    ReceiptHashService,
    {
      provide: RECEIPT_METADATA_REPOSITORY,
      useClass: SupabaseReceiptMetadataRepository,
    },
  ],
  exports: [ReceiptsService, ReceiptHashService],
})
export class ReceiptsModule {}
