import { Controller, Get, Query } from '@nestjs/common';
import { ApiOperation, ApiQuery, ApiResponse, ApiTags } from '@nestjs/swagger';
import { Throttle } from '@nestjs/throttler';
import { SearchService } from './search.service';
import {
  UnifiedSearchQueryDto,
  UnifiedSearchResponseDto,
} from './dto/unified-search.dto';

@ApiTags('search')
@Controller('search')
export class SearchController {
  constructor(private readonly searchService: SearchService) {}

  @Get()
  @Throttle({ default: { limit: 30, ttl: 60000 } })
  @ApiOperation({
    summary: 'Unified search for profiles and marketplace listings',
    description:
      'Consumes query parameter to search across public usernames and marketplace listings with typo tolerance (didYouMean).',
  })
  @ApiQuery({
    name: 'q',
    description: 'Search query (min 2 characters)',
    required: true,
    example: 'alice',
  })
  @ApiQuery({
    name: 'type',
    description: 'Filter scope (all, profiles, listings)',
    required: false,
    example: 'all',
  })
  @ApiQuery({
    name: 'limit',
    description: 'Max items per category (1-50)',
    required: false,
    example: 10,
  })
  @ApiResponse({
    status: 200,
    description: 'Unified search results including profiles and listings',
    type: UnifiedSearchResponseDto,
  })
  @ApiResponse({
    status: 400,
    description: 'Invalid search query',
  })
  async search(
    @Query() query: UnifiedSearchQueryDto,
  ): Promise<UnifiedSearchResponseDto> {
    return this.searchService.unifiedSearch(query);
  }
}
