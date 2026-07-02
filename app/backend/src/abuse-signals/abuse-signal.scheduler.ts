import { Injectable, Logger } from "@nestjs/common";
import { Cron, CronExpression } from "@nestjs/schedule";
import { AbuseSignalService } from "./abuse-signal.service";

@Injectable()
export class AbuseSignalScheduler {
  private readonly logger = new Logger(AbuseSignalScheduler.name);

  constructor(private readonly abuseSignalService: AbuseSignalService) {}

  @Cron(CronExpression.EVERY_DAY_AT_MIDNIGHT)
  async pruneExpiredSignals(): Promise<void> {
    this.logger.log("Running daily abuse signal retention cleanup...");
    const count = await this.abuseSignalService.pruneExpiredSignals();
    if (count > 0) {
      this.logger.log(`Retention cleanup complete: ${count} signals pruned`);
    }
  }
}
