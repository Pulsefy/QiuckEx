import { Controller, Post, Body, HttpCode, HttpStatus, HttpException } from '@nestjs/common';
import { LinksService } from './links.service';
import { LinkMetadataRequestDto, LinkMetadataResponseDto } from './dto';
import { LinkValidationError } from './errors';

@Controller('links')
export class LinksController {
  constructor(private readonly linksService: LinksService) {}

  @Post('metadata')
  @HttpCode(HttpStatus.OK)
  async generateMetadata(
    @Body() request: LinkMetadataRequestDto,
  ): Promise<{ success: boolean; data: LinkMetadataResponseDto }> {
    try {
      const metadata = await this.linksService.generateMetadata(request);
      return {
        success: true,
        data: metadata,
      };
    } catch (error) {
      if (error instanceof LinkValidationError) {
        throw new HttpException(
          {
            success: false,
            error: {
              code: error.code,
              message: error.message,
              field: error.field,
            },
          },
          HttpStatus.BAD_REQUEST,
        );
      }
      throw error;
    }
  }
}
