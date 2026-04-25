import {
  Controller,
  Post,
  Body,
  HttpCode,
  HttpStatus,
  BadRequestException,
  UseInterceptors,
  UploadedFile,
} from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiBody, ApiConsumes, ApiProperty } from '@nestjs/swagger';
import { FileInterceptor } from '@nestjs/platform-express';
import { BulkPaymentLinksService } from './bulk-payment-links.service';
import {
  BulkPaymentLinkRequestDto,
  BulkPaymentLinkResponseDto,
} from './dto/bulk-payment-link.dto';

@ApiTags('links')
@Controller('links/bulk')
export class BulkPaymentLinksController {
  constructor(private readonly bulkPaymentLinksService: BulkPaymentLinksService) {}

  @Post('generate')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Generate bulk payment links (JSON)',
    description:
      'Generate up to 500 payment links in a single request. Ideal for payroll, bulk invoicing, or mass payments.',
  })
  @ApiBody({ type: BulkPaymentLinkRequestDto })
  @ApiResponse({
    status: 200,
    description: 'Payment links generated successfully',
    type: BulkPaymentLinkResponseDto,
  })
  @ApiResponse({
    status: 400,
    description: 'Validation failed or batch size exceeded',
  })
  async generateBulkLinks(
    @Body() request: BulkPaymentLinkRequestDto,
  ): Promise<BulkPaymentLinkResponseDto> {
    return this.bulkPaymentLinksService.generateBulkLinks(request.links);
  }

  @Post('generate/csv')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Generate bulk payment links from CSV',
    description:
      'Upload a CSV file to generate payment links. CSV must have an "amount" column. Supports: amount, asset, memo, memoType, username, destination, referenceId, privacy, expirationDays, acceptedAssets (pipe-separated).',
  })
  @ApiConsumes('multipart/form-data')
  @ApiProperty({
    type: 'string',
    format: 'binary',
    description: 'CSV file with payment link data',
  })
  @ApiResponse({
    status: 200,
    description: 'Payment links generated successfully from CSV',
    type: BulkPaymentLinkResponseDto,
  })
  @ApiResponse({
    status: 400,
    description: 'Invalid CSV format or missing required columns',
  })
  @UseInterceptors(FileInterceptor('file'))
  async generateFromCSV(
    @UploadedFile() file: any,
  ): Promise<BulkPaymentLinkResponseDto> {
    if (!file) {
      throw new BadRequestException('CSV file is required');
    }

    if (!file.originalname.endsWith('.csv')) {
      throw new BadRequestException('File must be a CSV');
    }

    const csvContent = file.buffer.toString('utf-8');
    return this.bulkPaymentLinksService.generateFromCSV(csvContent);
  }
}
