import { Injectable, Logger, OnModuleInit } from "@nestjs/common";
import { StellarIngestionService } from "./stellar-ingestion.service";

/**
 * Reads the QUICKEX_CONTRACT_ID environment variable and starts streaming
 * once the NestJS application is ready.
 *
 * If no contract ID is configured the service logs a warning and skips.
 */
@Injectable()
export class IngestionBootstrapService implements OnModuleInit {
  private readonly logger = new Logger(IngestionBootstrapService.name);

  constructor(private readonly ingestion: StellarIngestionService) {}

  async onModuleInit(): Promise<void> {
    const contractId = process.env["QUICKEX_CONTRACT_ID"];

    if (!contractId) {
      this.logger.warn(
        "QUICKEX_CONTRACT_ID is not set; Stellar ingestion will NOT start. " +
          "Set this env var to enable event streaming.",
      );
      return;
    }

    this.logger.log(`Starting Stellar ingestion for contract ${contractId}`);
    await this.ingestion.startStreaming(contractId);
  }
}
