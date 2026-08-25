import { Injectable, Logger } from '@nestjs/common';
import { Cron, CronExpression } from '@nestjs/schedule';

import { PrivacyRetentionService } from './privacy-retention.service';

@Injectable()
export class PrivacyRetentionScheduler {
  private readonly logger = new Logger(PrivacyRetentionScheduler.name);

  constructor(private readonly retentionService: PrivacyRetentionService) {}

  @Cron(CronExpression.EVERY_DAY_AT_1AM)
  async enforceRetention(): Promise<void> {
    const result = await this.retentionService.enforceRetention();
    const affectedRows = result.results.reduce(
      (total, item) => total + item.affectedRows,
      0,
    );
    this.logger.log(
      `Privacy retention run completed at ${result.runAt}; affected ${affectedRows} rows`,
    );
  }
}

