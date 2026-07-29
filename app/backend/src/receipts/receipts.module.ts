/**
 * ReceiptsModule
 *
 * Location: app/backend/src/receipts/receipts.module.ts
 */

import { Module } from '@nestjs/common';
import { ReceiptsController } from './receipts.controller';
import { ReceiptsService } from './receipts.service';
import { ReceiptNormalizer } from './normalizers/receipt.normalizer';

@Module({
  controllers: [ReceiptsController],
  providers: [ReceiptsService, ReceiptNormalizer],
  exports: [ReceiptsService],
})
export class ReceiptsModule {}