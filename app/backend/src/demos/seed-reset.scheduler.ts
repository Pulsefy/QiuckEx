import {
  Injectable,
  Logger,
  OnModuleInit,
  OnModuleDestroy,
} from '@nestjs/common';
import { CronJob } from 'cron';
import { ConfigService } from '@nestjs/config';
import { EventEmitter2 } from '@nestjs/event-emitter';
import { DemoService, DemoSeedResult, DemoClearResult } from './demo.service';
import { JobQueueService } from '../job-queue/job-queue.service';
import { SeedResetReportDto, SeedResetOptionsDto, SeedResetStatusDto } from './dto/seed-reset.dto';

export interface SeedResetEventPayload {
  timestamp: string;
  success: boolean;
  report: SeedResetReportDto;
  trigger: string;
}

export class SeedResetEvent {
  constructor(
    public readonly payload: SeedResetEventPayload,
  ) {}
}

@Injectable()
export class SeedResetScheduler implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(SeedResetScheduler.name);
  private cronJob: CronJob | null = null;
  private lastResetTime: Date | null = null;
  private totalResets = 0;
  private successfulResets = 0;
  private failedResets = 0;
  private isResetting = false;
  private readonly exclusions: string[] = [];

  constructor(
    private readonly demoService: DemoService,
    private readonly rawConfigService: ConfigService,
    private readonly jobQueueService: JobQueueService,
    private readonly eventEmitter: EventEmitter2,
  ) {
    // Load exclusions from config
    this.exclusions = this.rawConfigService.get<string>('SEED_RESET_EXCLUSIONS', '')
      .split(',')
      .map((s) => s.trim().toLowerCase())
      .filter(Boolean);
  }

  async onModuleInit() {
    const enabled = this.isSeedResetEnabled();
    if (!enabled) {
      this.logger.log('Seed reset scheduler is disabled');
      return;
    }

    const interval = this.getCronInterval();
    this.logger.log(`Initializing seed reset scheduler with interval: ${interval}`);

    try {
      this.cronJob = new CronJob(
        interval,
        () => this.executeScheduledReset(),
        null,
        true,
        'UTC',
      );

      this.logger.log('Seed reset scheduler initialized successfully');
    } catch (error) {
      this.logger.error(
        `Failed to initialize seed reset scheduler: ${(error as Error).message}`,
      );
    }
  }

  async onModuleDestroy() {
    if (this.cronJob) {
      this.cronJob.stop();
      this.logger.log('Seed reset scheduler stopped');
    }
  }

  /**
   * Execute scheduled seed reset
   */
  private async executeScheduledReset(): Promise<void> {
    if (this.isResetting) {
      this.logger.warn('Previous reset still in progress, skipping...');
      return;
    }

    // Check if exclusions apply
    const excluded = await this.checkExclusions();
    if (excluded.length > 0) {
      this.logger.log(`Skipping reset due to exclusions: ${excluded.join(', ')}`);
      return;
    }

    this.logger.log('Executing scheduled seed reset...');
    await this.executeReset('scheduled');
  }

  /**
   * Execute a seed reset
   */
  private async executeReset(trigger: string): Promise<SeedResetReportDto> {
    this.isResetting = true;
    this.totalResets++;

    const startTime = new Date();
    const report: SeedResetReportDto = {
      timestamp: startTime.toISOString(),
      success: false,
      seededLinks: 0,
      seededTransactions: 0,
      skippedLinks: 0,
      skippedTransactions: 0,
      exclusionsApplied: [],
      errors: [],
      retryCount: 0,
      nextScheduled: this.getNextScheduledTime(),
    };

    try {
      // Step 1: Clear existing demo data
      this.logger.debug('Clearing existing demo data...');
      let clearResult: DemoClearResult;
      try {
        clearResult = await this.demoService.clear();
        this.logger.debug(
          `Cleared ${clearResult.deletedLinks} links and ${clearResult.deletedTransactions} transactions`,
        );
      } catch (error) {
        const errorMsg = `Failed to clear demo data: ${(error as Error).message}`;
        this.logger.error(errorMsg);
        report.errors.push(errorMsg);
        throw error;
      }

      // Step 2: Seed fresh demo data
      this.logger.debug('Seeding fresh demo data...');
      let seedResult: DemoSeedResult;
      try {
        seedResult = await this.demoService.seed();
        this.logger.debug(
          `Seeded ${seedResult.seededLinks} links and ${seedResult.seededTransactions} transactions`,
        );
        report.seededLinks = seedResult.seededLinks;
        report.seededTransactions = seedResult.seededTransactions;
        report.skippedLinks = seedResult.skippedLinks || 0;
        report.skippedTransactions = seedResult.skippedTransactions || 0;
      } catch (error) {
        const errorMsg = `Failed to seed demo data: ${(error as Error).message}`;
        this.logger.error(errorMsg);
        report.errors.push(errorMsg);
        throw error;
      }

      // Step 3: Mark success
      report.success = true;
      this.successfulResets++;
      this.lastResetTime = new Date();

      this.logger.log(
        `Seed reset completed successfully: ${seedResult.seededLinks} links, ${seedResult.seededTransactions} transactions seeded`,
      );

      // Emit event for monitoring
      await this.eventEmitter.emit(
        'seed.reset.completed',
        new SeedResetEvent({
          timestamp: startTime.toISOString(),
          success: true,
          report,
          trigger,
        }),
      );

    } catch (error) {
      this.failedResets++;
      const errorMsg = `Seed reset failed: ${(error as Error).message}`;
      this.logger.error(errorMsg);
      report.errors.push(errorMsg);
      report.success = false;

      // Emit failure event
      await this.eventEmitter.emit(
        'seed.reset.failed',
        new SeedResetEvent({
          timestamp: startTime.toISOString(),
          success: false,
          report,
          trigger,
        }),
      );

      // Retry logic if enabled
      const maxRetries = this.rawConfigService.get<number>('SEED_RESET_MAX_RETRIES', 3);
      const retryDelay = this.rawConfigService.get<number>('SEED_RESET_RETRY_DELAY_MS', 60000);

      if (maxRetries > 0 && report.retryCount! < maxRetries) {
        this.logger.log(`Scheduling retry ${report.retryCount! + 1} of ${maxRetries}...`);
        setTimeout(() => {
          report.retryCount = (report.retryCount || 0) + 1;
          this.executeReset('retry');
        }, retryDelay);
      }

    } finally {
      this.isResetting = false;
    }

    return report;
  }

  /**
   * Manual reset trigger
   */
  async manualReset(
    options: SeedResetOptionsDto = {},
  ): Promise<SeedResetReportDto> {
    this.logger.log(`Manual seed reset triggered: ${JSON.stringify(options)}`);

    const trigger = options.trigger || 'manual';
    const report = await this.executeReset(trigger);

    return report;
  }

  /**
   * Get current status of the seed reset scheduler
   */
  getStatus(): SeedResetStatusDto {
    const enabled = this.isSeedResetEnabled();
    const interval = this.getCronInterval();

    return {
      enabled,
      interval,
      lastResetTime: this.lastResetTime?.toISOString(),
      totalResets: this.totalResets,
      successfulResets: this.successfulResets,
      failedResets: this.failedResets,
      exclusions: this.exclusions.length > 0 ? this.exclusions : undefined,
    };
  }

  /**
   * Check if seed reset is enabled
   */
  private isSeedResetEnabled(): boolean {
    return this.rawConfigService.get<boolean>('SEED_RESET_ENABLED', false);
  }

  /**
   * Get cron interval from config or use default
   */
  private getCronInterval(): string {
    return this.rawConfigService.get<string>('SEED_RESET_INTERVAL', '0 0 * * *');
  }

  /**
   * Get next scheduled time
   */
  private getNextScheduledTime(): string | undefined {
    if (this.cronJob) {
      try {
        const next = this.cronJob.nextDate();
        return next.toISO() ?? undefined;
      } catch {
        return undefined;
      }
    }
    return undefined;
  }

  /**
   * Check if exclusions apply
   */
  private async checkExclusions(): Promise<string[]> {
    const applied: string[] = [];

    // Check environment exclusion
    const environment = this.rawConfigService.get<string>('NODE_ENV', 'development');
    if (this.exclusions.includes(environment)) {
      applied.push(`environment:${environment}`);
    }

    // Check network exclusion (should only run on testnet)
    const network = this.rawConfigService.get<string>('NETWORK', 'testnet');
    if (network !== 'testnet') {
      applied.push(`network:${network}`);
    }

    // Check if feature flag is enabled
    const featureEnabled = this.rawConfigService.get<boolean>('FEATURE_SEED_RESET', false);
    if (!featureEnabled) {
      applied.push('feature-flag:disabled');
    }

    // Check if demo mode is available
    try {
      await this.demoService.status();
    } catch {
      applied.push('demo-mode:unavailable');
    }

    return applied;
  }

  /**
   * Force a reset bypassing exclusions
   */
  async forceReset(
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    _options: SeedResetOptionsDto = {},
  ): Promise<SeedResetReportDto> {
    this.logger.warn('Force reset triggered, bypassing exclusions');
    const report = await this.executeReset('force');
    return report;
  }

  /**
   * Check if currently resetting
   */
  isRunning(): boolean {
    return this.isResetting;
  }
}