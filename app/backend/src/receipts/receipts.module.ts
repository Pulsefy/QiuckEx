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

@Module({
  controllers: [ReceiptsController],
  providers: [ReceiptsService, ReceiptNormalizer, ReceiptHashService],
  exports: [ReceiptsService, ReceiptHashService],
})
export class ReceiptsModule {}
