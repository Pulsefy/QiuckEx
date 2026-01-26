import { Controller, Post, Body, HttpCode, HttpStatus } from '@nestjs/common';
import { LinksService } from './links.service';
import { LinkMetadataRequestDto, LinkMetadataResponseDto } from './dto';

@Controller('links')
export class LinksController {
  constructor(private readonly linksService: LinksService) {}

  @Post('metadata')
  @HttpCode(HttpStatus.OK)
  async generateMetadata(
    @Body() request: LinkMetadataRequestDto,
  ): Promise<{ success: boolean; data: LinkMetadataResponseDto }> {
    const metadata = await this.linksService.generateMetadata(request);
    return {
      success: true,
      data: metadata,
    };
  }
}
