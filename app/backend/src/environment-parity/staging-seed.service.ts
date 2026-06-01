import { Injectable, Logger, OnModuleInit } from "@nestjs/common";
import { AppConfigService } from "../config/app-config.service";
import { SupabaseService } from "../supabase/supabase.service";

interface TestDataRecord {
  table: string;
  data: Record<string, unknown>;
}

/**
 * StagingSeedService provides safe test data seeding for staging environments.
 *
 * This service:
 * - Only operates when STAGING_SEED_DATA_ENABLED is true
 * - Creates test data that is clearly marked as test data
 * - Never modifies production data
 * - Uses test prefixes to identify seeded data
 * - Provides idempotent seeding (safe to run multiple times)
 *
 * All seeded data includes:
 * - is_test_data: true flag
 * - test_data_prefix: 'STAGING_SEED_' for easy identification
 * - created_at: timestamp
 * - Safe, non-sensitive test values
 */
@Injectable()
export class StagingSeedService implements OnModuleInit {
  private readonly logger = new Logger(StagingSeedService.name);
  private readonly TEST_PREFIX = "STAGING_SEED_";
  private seeded = false;

  constructor(
    private readonly config: AppConfigService,
    private readonly supabase: SupabaseService,
  ) {}

  async onModuleInit() {
    if (this.config.stagingSeedDataEnabled && !this.seeded) {
      await this.seedTestData();
    }
  }

  /**
   * Seed test data for staging environment
   * This is idempotent and safe to run multiple times
   */
  async seedTestData(): Promise<void> {
    if (this.seeded) {
      this.logger.log("Test data already seeded, skipping...");
      return;
    }

    if (!this.config.stagingSeedDataEnabled) {
      this.logger.warn("Staging seed data is not enabled");
      return;
    }

    this.logger.log("Starting staging test data seeding...");

    try {
      // Check if test data already exists
      const existingData = await this.checkExistingTestData();
      if (existingData > 0) {
        this.logger.log(
          `Found ${existingData} existing test records, skipping seed`,
        );
        this.seeded = true;
        return;
      }

      // Seed test data
      const records = this.getTestDataRecords();
      let seededCount = 0;

      for (const record of records) {
        try {
          await this.insertTestRecord(record);
          seededCount++;
        } catch (error) {
          this.logger.error(
            `Failed to seed test data for ${record.table}: ${error.message}`,
          );
        }
      }

      this.seeded = true;
      this.logger.log(`Successfully seeded ${seededCount} test records`);
    } catch (error) {
      this.logger.error(`Failed to seed test data: ${error.message}`);
    }
  }

  /**
   * Check if test data already exists
   */
  private async checkExistingTestData(): Promise<number> {
    try {
      const { data, error } = await this.supabase
        .getClient()
        .from("usernames")
        .select("id", { count: "exact", head: true })
        .ilike("username", `${this.TEST_PREFIX}%`);

      if (error) {
        this.logger.warn(`Error checking existing test data: ${error.message}`);
        return 0;
      }

      return data?.length || 0;
    } catch (error) {
      this.logger.warn(`Error checking existing test data: ${error.message}`);
      return 0;
    }
  }

  /**
   * Get test data records to seed
   */
  private getTestDataRecords(): TestDataRecord[] {
    const timestamp = new Date().toISOString();

    return [
      // Test usernames
      {
        table: "usernames",
        data: {
          username: `${this.TEST_PREFIX}TEST_USER_1`,
          wallet_address:
            "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF",
          is_test_data: true,
          test_data_label: "Test User 1",
          created_at: timestamp,
        },
      },
      {
        table: "usernames",
        data: {
          username: `${this.TEST_PREFIX}TEST_USER_2`,
          wallet_address:
            "GBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBHF",
          is_test_data: true,
          test_data_label: "Test User 2",
          created_at: timestamp,
        },
      },
      {
        table: "usernames",
        data: {
          username: `${this.TEST_PREFIX}TEST_USER_3`,
          wallet_address:
            "GCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCHHF",
          is_test_data: true,
          test_data_label: "Test User 3",
          created_at: timestamp,
        },
      },
    ];
  }

  /**
   * Insert a single test record
   */
  private async insertTestRecord(record: TestDataRecord): Promise<void> {
    const { error } = await this.supabase
      .getClient()
      .from(record.table)
      .insert(record.data);

    if (error) {
      throw new Error(
        `Failed to insert into ${record.table}: ${error.message}`,
      );
    }

    this.logger.debug(`Seeded test data: ${record.table}`);
  }

  /**
   * Clean up all test data (use with caution)
   */
  async cleanupTestData(): Promise<void> {
    this.logger.warn("Cleaning up all test data...");

    try {
      const { error } = await this.supabase
        .getClient()
        .from("usernames")
        .delete()
        .ilike("username", `${this.TEST_PREFIX}%`);

      if (error) {
        throw new Error(`Failed to cleanup test data: ${error.message}`);
      }

      this.logger.log("Test data cleanup complete");
    } catch (error) {
      this.logger.error(`Test data cleanup failed: ${error.message}`);
      throw error;
    }
  }

  /**
   * Check if seeding has been completed
   */
  isSeeded(): boolean {
    return this.seeded;
  }
}
