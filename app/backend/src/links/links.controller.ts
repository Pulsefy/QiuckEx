import {
  Controller,
  Post,
  Body,
  HttpCode,
  HttpStatus,
  BadRequestException,
  UseGuards,
} from "@nestjs/common";
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiBody,
  ApiHeader,
} from "@nestjs/swagger";
import { LinksService } from "./links.service";
import { LinkMetadataRequestDto, LinkMetadataResponseDto } from "../dto";
import { LinkValidationError } from "./errors";
import { ApiKeyGuard } from "../auth/guards/api-key.guard";

@ApiTags("links")
@ApiHeader({
  name: "X-API-Key",
  description:
    "Optional API key for higher rate limits (120 req/min vs 20 req/min)",
  required: false,
})
@UseGuards(ApiKeyGuard)
@Controller("links")
export class LinksController {
  constructor(private readonly linksService: LinksService) {}

  @Post("metadata")
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: "Generate canonical link metadata",
    description:
      "Validates payment link parameters and generates canonical metadata for frontend consumption",
  })
  @ApiBody({ type: LinkMetadataRequestDto })
  @ApiResponse({
    status: 200,
    description: "Metadata generated successfully",
    type: LinkMetadataResponseDto,
  })
  @ApiResponse({
    status: 400,
    description: "Validation failed",
  })
  @ApiResponse({
    status: 429,
    description: "Rate limit exceeded – retry after 60 seconds",
  })
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
        throw new BadRequestException({
          code: error.code,
          message: error.message,
          field: error.field,
        });
      }
      throw error;
    }
  }
}
