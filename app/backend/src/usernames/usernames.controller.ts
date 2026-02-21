import {
  Body,
  Controller,
  Get,
  Post,
  Query,
  ConflictException,
  BadRequestException,
  ForbiddenException,
} from "@nestjs/common";
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
} from "../dto";
import { UsernamesService } from "./usernames.service";
import {
  UsernameConflictError,
  UsernameLimitExceededError,
  UsernameValidationError,
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
}
