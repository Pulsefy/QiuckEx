import { Injectable, Logger, OnModuleInit } from "@nestjs/common";
import { Cron, CronExpression } from "@nestjs/schedule";
import { AppConfigService } from "../config";
import { HORIZON_BASE_URLS } from "../config/stellar.config";
import { IndexerCheckpointRepository } from "../ingestion/indexer-checkpoint.repository";
import { MetricsService } from "../metrics/metrics.service";

export interface IndexerLagStatus {
  currentNetworkLedger: number | null;
  lastIndexedLedger: number | null;
  lagLedgers: number | null;
  isLagging: boolean;
  isEnabled: boolean;
  isOverridden: boolean;
  thresholdLedgers: number;
}

@Injectable()
export class IndexerLagService implements OnModuleInit {
  private readonly logger = new Logger(IndexerLagService.name);
  private readonly horizonUrl: string;
  private currentNetworkLedger: number | null = null;
  private lastIndexedLedger: number | null = null;

  constructor(
    private readonly config: AppConfigService,
    private readonly checkpointRepo: IndexerCheckpointRepository,
    private readonly metrics: MetricsService,
  ) {
    this.horizonUrl = HORIZON_BASE_URLS[this.config.network];
  }

  onModuleInit() {
    this.pollHorizon();
  }

  @Cron(CronExpression.EVERY_MINUTE)
  async pollHorizon() {
    try {
      const res = await fetch(`${this.horizonUrl}`, {
        headers: { Accept: "application/json" },
      });
      if (!res.ok) throw new Error(`Horizon returned ${res.status}`);
      const body = (await res.json()) as {
        core_latest_ledger?: number;
        history_latest_ledger?: number;
      };
      const ledger = body.core_latest_ledger ?? body.history_latest_ledger;
      if (ledger !== undefined) {
        this.currentNetworkLedger = ledger;
      }
    } catch (error) {
      this.logger.error("Failed to fetch current network ledger", error);
    }

    if (this.config.quickexContractId) {
      try {
        const lastIndexed = await this.checkpointRepo.getLastLedger(
          this.config.quickexContractId,
        );
        if (lastIndexed !== null) {
          this.lastIndexedLedger = lastIndexed;
        }
      } catch (error) {
        this.logger.error("Failed to fetch last indexed ledger", error);
      }
    }

    this.updateMetrics();
  }

  getStatus(): IndexerLagStatus {
    let lagLedgers: number | null = null;
    if (
      this.currentNetworkLedger !== null &&
      this.lastIndexedLedger !== null
    ) {
      lagLedgers = Math.max(
        0,
        this.currentNetworkLedger - this.lastIndexedLedger,
      );
    }

    return {
      currentNetworkLedger: this.currentNetworkLedger,
      lastIndexedLedger: this.lastIndexedLedger,
      lagLedgers,
      isLagging:
        lagLedgers !== null &&
        lagLedgers > this.config.indexerLagThresholdLedgers,
      isEnabled: this.config.indexerLagGuardEnabled,
      isOverridden: this.config.indexerLagGuardOverride,
      thresholdLedgers: this.config.indexerLagThresholdLedgers,
    };
  }

  isBlocked(): boolean {
    const status = this.getStatus();
    if (!status.isEnabled) return false;
    if (status.isOverridden) return false;
    return status.isLagging;
  }

  private updateMetrics() {
    const status = this.getStatus();
    if (status.lagLedgers !== null) {
      this.metrics.recordIndexerLag(status.lagLedgers);
    }
    if (!status.isEnabled) {
      this.metrics.setIndexerLagGuardStatus(0);
    } else if (status.isOverridden) {
      this.metrics.setIndexerLagGuardStatus(2);
    } else if (status.isLagging) {
      this.metrics.setIndexerLagGuardStatus(3);
    } else {
      this.metrics.setIndexerLagGuardStatus(1);
    }
  }
}
