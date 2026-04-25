import {
  Body,
  Controller,
  Get,
  Post,
  Query,
  ConflictException,
  BadRequestException,
  ForbiddenException,
  NotFoundException,
} from "@nestjs/common";
import { Throttle } from "@nestjs/throttler";
// import { RateLimitGroup } from "../config/rate-limit.config";
import {
  ApiBody,
  ApiOperation,
  ApiQuery,
  ApiResponse,
  ApiTags,
} from "@nestjs/swagger";
import { EventEmitter2 } from "@nestjs/event-emitter";

import {
  CreateUsernameDto,
  CreateUsernameResponseDto,
  ListUsernamesQueryDto,
  ListUsernamesResponseDto,
  SearchUsernamesQueryDto,
  SearchUsernamesResponseDto,
  TrendingCreatorsQueryDto,
  TrendingCreatorsResponseDto,
  RecentlyActiveQueryDto,
  RecentlyActiveResponseDto,
  PublicProfileDto,
} from "../dto";
import { UsernamesService } from "./usernames.service";
import {
  UsernameConflictError,
  UsernameLimitExceededError,
  UsernameValidationError,
  UsernameErrorCode,
} from "./errors";

@ApiTags("usernames")
@Controller("username")
export class UsernamesController {
  constructor(
    private readonly usernamesService: UsernamesService,
    private readonly eventEmitter: EventEmitter2,
  ) {}

  @Post()
  @ApiOperation({
    summary: "Create a new username",
    description:
      "Registers a new username for a user. Username must be 3-32 characters, " +
      "lowercase alphanumeric with underscores only. Uniqueness is enforced; " +
      "duplicate username returns 409 Conflict.",
  })
  @ApiBody({
    type: CreateUsernameDto,
    description: "Username creation payload",
  })
  @ApiResponse({
    status: 201,
    description: "Username created successfully",
    type: CreateUsernameResponseDto,
  })
  @ApiResponse({
    status: 400,
    description: "Invalid username format or validation failed",
  })
  @ApiResponse({
    status: 409,
    description: "Username already taken (conflict)",
  })
  @ApiResponse({
    status: 403,
    description: "Wallet has reached the maximum allowed usernames",
  })
  async createUsername(
    @Body() body: CreateUsernameDto,
  ): Promise<CreateUsernameResponseDto> {
    try {
      await this.usernamesService.create(body.username, body.publicKey);
    } catch (err) {
      if (err instanceof UsernameConflictError) {
        throw new ConflictException({
          code: "USERNAME_CONFLICT",
          message: err.message,
        });
      }
      if (err instanceof UsernameLimitExceededError) {
        throw new ForbiddenException({
          code: "USERNAME_LIMIT_EXCEEDED",
          message: err.message,
        });
      }
      if (err instanceof UsernameValidationError) {
        throw new BadRequestException({
          code: err.code,
          message: err.message,
          field: err.field,
        });
      }
      throw err;
    }

    this.eventEmitter.emit("username.claimed", {
      username: body.username,
      publicKey: body.publicKey,
      timestamp: new Date().toISOString(),
    });

    return { ok: true };
  }

  @Get()
  @ApiOperation({
    summary: "List usernames for a wallet",
    description:
      "Returns all usernames registered for the given Stellar public key.",
  })
  @ApiQuery({
    name: "publicKey",
    description: "Stellar public key of the wallet",
    required: true,
  })
  @ApiResponse({
    status: 200,
    description: "List of usernames",
    type: ListUsernamesResponseDto,
  })
  @ApiResponse({
    status: 400,
    description: "Invalid or missing publicKey",
  })
  async listUsernames(
    @Query() query: ListUsernamesQueryDto,
  ): Promise<ListUsernamesResponseDto> {
    const usernames = await this.usernamesService.listByPublicKey(
      query.publicKey,
    );
    return { usernames };
  }

  @Get("search")
  @Throttle({ default: { limit: 20, ttl: 60000 } }) // 20 requests per minute
  @ApiOperation({
    summary: "Search public profiles",
    description:
      "Fuzzy search for public usernames. Returns profiles sorted by similarity score. " +
      'Only profiles with "Public Profile" enabled will appear in search results.',
  })
  @ApiQuery({
    name: "query",
    description: "Search query for fuzzy matching (min 2 characters)",
    required: true,
    example: "alice",
  })
  @ApiQuery({
    name: "limit",
    description: "Maximum number of results (1-100)",
    required: false,
    example: 10,
  })
  @ApiResponse({
    status: 200,
    description: "List of public profiles matching the search query",
    type: SearchUsernamesResponseDto,
  })
  @ApiResponse({
    status: 400,
    description: "Invalid search query",
  })
  async searchUsernames(
    @Query() query: SearchUsernamesQueryDto,
  ): Promise<SearchUsernamesResponseDto> {
    const results = await this.usernamesService.searchPublicUsernames(
      query.query,
      query.limit,
    );

    return {
      profiles: results.map((r) => ({
        id: r.id,
        username: r.username,
        publicKey: r.public_key,
        lastActiveAt: r.last_active_at || r.created_at,
        createdAt: r.created_at,
        similarityScore: r.similarity_score,
      })) as PublicProfileDto[],
      total: results.length,
    };
  }

  @Get("trending")
  @Throttle({ default: { limit: 10, ttl: 60000 } }) // 10 requests per minute
  @ApiOperation({
    summary: "Get trending creators",
    description:
      "Returns trending creator profiles based on transaction volume. " +
      "Ranking is calculated from recent payment activity within the specified time window.",
  })
  @ApiQuery({
    name: "timeWindowHours",
    description: "Time window in hours for trending calculation (1-720)",
    required: false,
    example: 24,
  })
  @ApiQuery({
    name: "limit",
    description: "Maximum number of trending creators (1-100)",
    required: false,
    example: 10,
  })
  @ApiResponse({
    status: 200,
    description: "List of trending creator profiles sorted by volume",
    type: TrendingCreatorsResponseDto,
  })
  @ApiResponse({
    status: 400,
    description: "Invalid time window parameter",
  })
  async getTrendingCreators(
    @Query() query: TrendingCreatorsQueryDto,
  ): Promise<TrendingCreatorsResponseDto> {
    const creators = await this.usernamesService.getTrendingCreators(
      query.timeWindowHours,
      query.limit,
    );

    return {
      creators: creators.map((c) => ({
        id: c.id,
        username: c.username,
        publicKey: c.public_key,
        lastActiveAt: c.last_active_at || c.created_at,
        createdAt: c.created_at,
        transactionVolume: c.transaction_volume,
        transactionCount: c.transaction_count,
      })) as PublicProfileDto[],
      timeWindowHours: query.timeWindowHours,
      calculatedAt: new Date().toISOString(),
    };
  }

  @Get("recently-active")
  @Throttle({ default: { limit: 10, ttl: 60000 } }) // 10 requests per minute
  @ApiOperation({
    summary: "Get recently active users",
    description:
      "Returns users who have been recently active based on payment activity. " +
      "Users are sorted by their most recent transaction or profile activity.",
  })
  @ApiQuery({
    name: "timeWindowHours",
    description:
      "Time window in hours to consider users as recently active (1-168)",
    required: false,
    example: 24,
  })
  @ApiQuery({
    name: "limit",
    description: "Maximum number of recently active users (1-100)",
    required: false,
    example: 10,
  })
  @ApiResponse({
    status: 200,
    description:
      "List of recently active public profiles sorted by last activity",
    type: RecentlyActiveResponseDto,
  })
  @ApiResponse({
    status: 400,
    description: "Invalid time window parameter",
  })
  async getRecentlyActive(
    @Query() query: RecentlyActiveQueryDto,
  ): Promise<RecentlyActiveResponseDto> {
    const users = await this.usernamesService.getRecentlyActiveUsers(
      query.timeWindowHours,
      query.limit,
    );

    return {
      users: users.map((u) => ({
        id: u.id,
        username: u.username,
        publicKey: u.public_key,
        lastActiveAt: u.last_active_at || u.created_at,
        createdAt: u.created_at,
      })) as PublicProfileDto[],
      timeWindowHours: query.timeWindowHours,
      calculatedAt: new Date().toISOString(),
    };
  }

  @Post("toggle-public")
  @ApiOperation({
    summary: "Toggle public profile visibility",
    description:
      "Enable or disable public profile visibility for a username. " +
      "Only the wallet owner can toggle their profile visibility.",
  })
  @ApiBody({
    schema: {
      type: "object",
      properties: {
        username: { type: "string", example: "alice" },
        publicKey: {
          type: "string",
          example: "GBXGQ55JMQ4L2B6E7S8Y9Z0A1B2C3D4E5F6G7H8I7YWR",
        },
        isPublic: { type: "boolean", example: true },
      },
      required: ["username", "publicKey", "isPublic"],
    },
  })
  @ApiResponse({
    status: 200,
    description: "Public profile visibility toggled successfully",
  })
  @ApiResponse({
    status: 404,
    description: "Username not found or does not belong to this wallet",
  })
  @ApiResponse({
    status: 400,
    description: "Invalid username format",
  })
  async togglePublicProfile(
    @Body() body: { username: string; publicKey: string; isPublic: boolean },
  ): Promise<{ ok: boolean }> {
    try {
      await this.usernamesService.togglePublicProfile(
        body.username,
        body.publicKey,
        body.isPublic,
      );
      return { ok: true };
    } catch (err) {
      if (err instanceof UsernameValidationError) {
        if (err.code === UsernameErrorCode.NOT_FOUND) {
          throw new NotFoundException({
            code: UsernameErrorCode.NOT_FOUND,
            message: err.message,
          });
        }
        throw new BadRequestException({
          code: err.code,
          message: err.message,
        });
      }
      throw err;
    }
  }
}
