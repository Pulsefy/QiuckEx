import {
  Controller,
  Post,
  Body,
  HttpCode,
  HttpStatus,
  BadRequestException,
  UseGuards,
  UseInterceptors,
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
import {
  IdempotencyInterceptor,
  IDEMPOTENCY_KEY_HEADER,
} from "../common/idempotency/idempotency.interceptor";

@ApiTags("links")
@ApiHeader({
  name: "X-API-Key",
  description:
    "Optional API key for higher rate limits (120 req/min vs 20 req/min)",
  required: false,
})
@ApiHeader({
  name: IDEMPOTENCY_KEY_HEADER,
  description:
    "Optional. Supply a unique key to make this mutation idempotent: retries with the same key and body return the original response; reuse with a different body is rejected.",
  required: false,
})
@UseGuards(ApiKeyGuard)
@UseInterceptors(IdempotencyInterceptor)
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
