import { Module } from "@nestjs/common";
import { ScamAlertsController } from "./scam-alerts.controller";
import { ScamAlertsService } from "./scam-alerts.service";

@Module({
	controllers: [ScamAlertsController],
	providers: [ScamAlertsService],
	exports: [ScamAlertsService],
})
export class ScamAlertsModule {}
