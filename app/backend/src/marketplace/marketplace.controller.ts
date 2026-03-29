import {
  Body,
  Controller,
  Delete,
  Get,
  NotFoundException,
  Param,
  Post,
  Query,
  BadRequestException,
  ForbiddenException,
  ConflictException,
} from '@nestjs/common';
import {
  ApiBody,
  ApiOperation,
  ApiParam,
  ApiQuery,
  ApiResponse,
  ApiTags,
} from '@nestjs/swagger';

import { MarketplaceService } from './marketplace.service';
import { ListUsernameDto, PlaceBidDto, AcceptBidDto, CancelListingDto } from './dto';
import { MarketplaceError, MarketplaceErrorCode } from './errors';

@ApiTags('marketplace')
@Controller('marketplace')
export class MarketplaceController {
  constructor(private readonly marketplaceService: MarketplaceService) {}

  @Post('list')
  @ApiOperation({ summary: 'List a username for sale' })
  @ApiBody({ type: ListUsernameDto })
  @ApiResponse({ status: 201, description: 'Listing created' })
  @ApiResponse({ status: 400, description: 'Invalid input' })
  @ApiResponse({ status: 403, description: 'Username not owned by this wallet' })
  @ApiResponse({ status: 409, description: 'Username already listed' })
  async listUsername(@Body() body: ListUsernameDto) {
    try {
      const listing = await this.marketplaceService.listUsername(
        body.username,
        body.sellerPublicKey,
        body.askingPrice,
      );
      return { listing };
    } catch (err) {
      if (err instanceof MarketplaceError) {
        this.throwHttp(err);
      }
      throw err;
    }
  }

  @Get()
  @ApiOperation({ summary: 'Get all active listings' })
  @ApiQuery({ name: 'limit', required: false, example: 20 })
  @ApiQuery({ name: 'offset', required: false, example: 0 })
  @ApiResponse({ status: 200, description: 'List of active listings' })
  async getActiveListings(
    @Query('limit') limit = 20,
    @Query('offset') offset = 0,
  ) {
    const { listings, total } = await this.marketplaceService.getActiveListings(
      Number(limit),
      Number(offset),
    );
    return { listings, total };
  }

  @Get(':listingId')
  @ApiOperation({ summary: 'Get a specific listing' })
  @ApiParam({ name: 'listingId', description: 'Listing UUID' })
  @ApiResponse({ status: 200, description: 'Listing details' })
  @ApiResponse({ status: 404, description: 'Listing not found' })
  async getListing(@Param('listingId') listingId: string) {
    try {
      const listing = await this.marketplaceService.getListing(listingId);
      return { listing };
    } catch (err) {
      if (err instanceof MarketplaceError) {
        this.throwHttp(err);
      }
      throw err;
    }
  }

  @Delete(':listingId')
  @ApiOperation({ summary: 'Cancel a listing' })
  @ApiParam({ name: 'listingId', description: 'Listing UUID' })
  @ApiBody({ type: CancelListingDto })
  @ApiResponse({ status: 200, description: 'Listing cancelled' })
  @ApiResponse({ status: 403, description: 'Not the seller' })
  @ApiResponse({ status: 404, description: 'Listing not found' })
  async cancelListing(
    @Param('listingId') listingId: string,
    @Body() body: CancelListingDto,
  ) {
    try {
      await this.marketplaceService.cancelListing(listingId, body.sellerPublicKey);
      return { ok: true };
    } catch (err) {
      if (err instanceof MarketplaceError) {
        this.throwHttp(err);
      }
      throw err;
    }
  }

  @Post(':listingId/bid')
  @ApiOperation({ summary: 'Place a bid on a listing' })
  @ApiParam({ name: 'listingId', description: 'Listing UUID' })
  @ApiBody({ type: PlaceBidDto })
  @ApiResponse({ status: 201, description: 'Bid placed' })
  @ApiResponse({ status: 400, description: 'Seller cannot bid on own listing' })
  @ApiResponse({ status: 404, description: 'Listing not found' })
  async placeBid(
    @Param('listingId') listingId: string,
    @Body() body: PlaceBidDto,
  ) {
    try {
      const bid = await this.marketplaceService.placeBid(
        listingId,
        body.bidderPublicKey,
        body.bidAmount,
      );
      return { bid };
    } catch (err) {
      if (err instanceof MarketplaceError) {
        this.throwHttp(err);
      }
      throw err;
    }
  }

  @Get(':listingId/bids')
  @ApiOperation({ summary: 'Get all bids for a listing' })
  @ApiParam({ name: 'listingId', description: 'Listing UUID' })
  @ApiResponse({ status: 200, description: 'List of bids' })
  @ApiResponse({ status: 404, description: 'Listing not found' })
  async getBids(@Param('listingId') listingId: string) {
    try {
      const bids = await this.marketplaceService.getBids(listingId);
      return { bids };
    } catch (err) {
      if (err instanceof MarketplaceError) {
        this.throwHttp(err);
      }
      throw err;
    }
  }

  @Post(':listingId/accept-bid/:bidId')
  @ApiOperation({ summary: 'Accept a bid — atomically transfers username ownership' })
  @ApiParam({ name: 'listingId', description: 'Listing UUID' })
  @ApiParam({ name: 'bidId', description: 'Bid UUID' })
  @ApiBody({ type: AcceptBidDto })
  @ApiResponse({ status: 200, description: 'Bid accepted and ownership transferred' })
  @ApiResponse({ status: 400, description: 'Bid not pending or listing not active' })
  @ApiResponse({ status: 403, description: 'Not the seller' })
  @ApiResponse({ status: 404, description: 'Listing or bid not found' })
  async acceptBid(
    @Param('listingId') listingId: string,
    @Param('bidId') bidId: string,
    @Body() body: AcceptBidDto,
  ) {
    try {
      await this.marketplaceService.acceptBid(listingId, bidId, body.sellerPublicKey);
      return { ok: true };
    } catch (err) {
      if (err instanceof MarketplaceError) {
        this.throwHttp(err);
      }
      throw err;
    }
  }

  private throwHttp(err: MarketplaceError): never {
    switch (err.code) {
      case MarketplaceErrorCode.LISTING_NOT_FOUND:
      case MarketplaceErrorCode.BID_NOT_FOUND:
        throw new NotFoundException({ code: err.code, message: err.message });
      case MarketplaceErrorCode.UNAUTHORIZED:
      case MarketplaceErrorCode.USERNAME_NOT_OWNED:
        throw new ForbiddenException({ code: err.code, message: err.message });
      case MarketplaceErrorCode.ALREADY_LISTED:
        throw new ConflictException({ code: err.code, message: err.message });
      default:
        throw new BadRequestException({ code: err.code, message: err.message });
    }
  }
}
