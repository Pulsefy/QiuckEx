import { Module } from "@nestjs/common";
import { HorizonService } from "../transactions/horizon.service";
import { PaymentsController } from "./payments.controller";

@Module({
  imports: [],
  controllers: [PaymentsController],
  providers: [HorizonService],
  exports: [],
})
export class PaymentsModule {}
