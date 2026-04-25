import { Injectable, Logger, BadRequestException } from '@nestjs/common';
import { LinksService } from './links.service';
import {
  BulkPaymentLinkItemDto,
  BulkPaymentLinkResponseItemDto,
  BulkPaymentLinkResponseDto,
} from './dto/bulk-payment-link.dto';
import { LinkMetadataRequestDto } from '../dto';
import { v4 as uuidv4 } from 'uuid';

@Injectable()
export class BulkPaymentLinksService {
  private readonly logger = new Logger(BulkPaymentLinksService.name);
  private readonly MAX_LINKS_PER_REQUEST = 500;

  constructor(private readonly linksService: LinksService) {}

  /**
   * Generate multiple payment links in bulk from JSON array
   * @param items - Array of payment link items
   * @returns Bulk response with all generated links
   */
  async generateBulkLinks(
    items: BulkPaymentLinkItemDto[],
  ): Promise<BulkPaymentLinkResponseDto> {
    const startTime = Date.now();

    // Validate batch size
    if (items.length === 0) {
      throw new BadRequestException('At least one payment link item is required');
    }

    if (items.length > this.MAX_LINKS_PER_REQUEST) {
      throw new BadRequestException(
        `Maximum ${this.MAX_LINKS_PER_REQUEST} links per request. Received: ${items.length}`,
      );
    }

    this.logger.log(`Generating ${items.length} payment links in bulk`);

    // Process all links in parallel with concurrency control
    const results: BulkPaymentLinkResponseItemDto[] = [];
    const errors: { index: number; error: string }[] = [];

    // Process in batches of 50 to avoid overwhelming the system
    const batchSize = 50;
    for (let i = 0; i < items.length; i += batchSize) {
      const batch = items.slice(i, i + batchSize);
      const batchPromises = batch.map(async (item, batchIndex) => {
        const index = i + batchIndex;
        try {
          const link = await this.generateSingleLink(item, index);
          return { success: true, link, index };
        } catch (error) {
          const errorMessage = error instanceof Error ? error.message : 'Unknown error';
          return { success: false, error: errorMessage, index };
        }
      });

      const batchResults = await Promise.all(batchPromises);

      for (const result of batchResults) {
        if (result.success && result.link) {
          results.push(result.link);
        } else if (!result.success) {
          errors.push({ index: result.index, error: result.error });
        }
      }
    }

    // If any errors occurred, throw with details
    if (errors.length > 0) {
      const errorDetails = errors
        .slice(0, 5)
        .map((e) => `Item ${e.index}: ${e.error}`)
        .join('; ');
      throw new BadRequestException(
        `Failed to generate ${errors.length} link(s). ${errorDetails}${errors.length > 5 ? '...' : ''}`,
      );
    }

    const processingTime = Date.now() - startTime;

    this.logger.log(
      `Successfully generated ${results.length} payment links in ${processingTime}ms`,
    );

    return {
      success: true,
      total: results.length,
      links: results,
      processingTimeMs: processingTime,
    };
  }

  /**
   * Parse CSV content and generate payment links
   * @param csvContent - CSV string with headers
   * @returns Bulk response with all generated links
   */
  async generateFromCSV(csvContent: string): Promise<BulkPaymentLinkResponseDto> {
    const startTime = Date.now();

    this.logger.log('Parsing CSV for bulk payment link generation');

    // Parse CSV
    const items = this.parseCSV(csvContent);

    if (items.length === 0) {
      throw new BadRequestException('No valid payment link items found in CSV');
    }

    this.logger.log(`Parsed ${items.length} items from CSV`);

    // Generate links
    return this.generateBulkLinks(items);
  }

  /**
   * Generate a single payment link
   * @param item - Payment link item
   * @param index - Index in the batch
   * @returns Generated link response
   */
  private async generateSingleLink(
    item: BulkPaymentLinkItemDto,
    index: number,
  ): Promise<BulkPaymentLinkResponseItemDto> {
    // Convert to LinkMetadataRequestDto
    const request: LinkMetadataRequestDto = {
      amount: item.amount,
      asset: item.asset,
      memo: item.memo,
      memoType: item.memoType as 'text' | 'id' | 'hash' | 'return',
      username: item.username,
      destination: item.destination,
      referenceId: item.referenceId,
      privacy: item.privacy,
      expirationDays: item.expirationDays,
      acceptedAssets: item.acceptedAssets,
    };

    // Generate metadata using existing service
    const metadata = await this.linksService.generateMetadata(request);

    // Generate unique ID
    const id = `link_${uuidv4().substring(0, 12)}`;

    // Build shareable URL
    const url = `https://app.quickex.to/pay?${metadata.canonical}`;

    return {
      id,
      canonical: metadata.canonical,
      url,
      amount: metadata.amount,
      asset: metadata.asset,
      username: metadata.username || undefined,
      destination: metadata.destination || undefined,
      referenceId: metadata.referenceId || undefined,
      index,
    };
  }

  /**
   * Parse CSV content into payment link items
   * Supports headers: amount, asset, memo, memoType, username, destination, referenceId, privacy, expirationDays, acceptedAssets
   * @param csvContent - CSV string
   * @returns Array of payment link items
   */
  private parseCSV(csvContent: string): BulkPaymentLinkItemDto[] {
    const lines = csvContent
      .split('\n')
      .map((line) => line.trim())
      .filter((line) => line.length > 0);

    if (lines.length < 2) {
      return [];
    }

    // Parse headers
    const headers = lines[0].split(',').map((h) => h.trim().toLowerCase());

    // Validate required header
    if (!headers.includes('amount')) {
      throw new BadRequestException('CSV must contain "amount" column');
    }

    const items: BulkPaymentLinkItemDto[] = [];

    // Parse data rows
    for (let i = 1; i < lines.length; i++) {
      const values = this.parseCSVLine(lines[i]);

      if (values.length !== headers.length) {
        this.logger.warn(`Skipping line ${i + 1}: column count mismatch`);
        continue;
      }

      // Map CSV row to DTO
      const row: Record<string, string> = {};
      headers.forEach((header, index) => {
        row[header] = values[index];
      });

      const item: BulkPaymentLinkItemDto = {
        amount: parseFloat(row.amount),
      };

      if (row.asset) item.asset = row.asset;
      if (row.memo) item.memo = row.memo;
      if (row.memotype) item.memoType = row.memoType;
      if (row.username) item.username = row.username;
      if (row.destination) item.destination = row.destination;
      if (row.referenceid) item.referenceId = row.referenceId;
      if (row.privacy) item.privacy = row.privacy.toLowerCase() === 'true';
      if (row.expirationdays) item.expirationDays = parseInt(row.expirationDays, 10);
      if (row.acceptedassets) {
        item.acceptedAssets = row.acceptedAssets
          .split('|')
          .map((a) => a.trim())
          .filter((a) => a.length > 0);
      }

      // Validate amount
      if (isNaN(item.amount) || item.amount <= 0) {
        this.logger.warn(`Skipping line ${i + 1}: invalid amount`);
        continue;
      }

      items.push(item);
    }

    return items;
  }

  /**
   * Parse a single CSV line, handling quoted values
   * @param line - CSV line
   * @returns Array of values
   */
  private parseCSVLine(line: string): string[] {
    const values: string[] = [];
    let current = '';
    let inQuotes = false;

    for (let i = 0; i < line.length; i++) {
      const char = line[i];

      if (char === '"') {
        inQuotes = !inQuotes;
      } else if (char === ',' && !inQuotes) {
        values.push(current.trim());
        current = '';
      } else {
        current += char;
      }
    }

    values.push(current.trim());
    return values;
  }
}
