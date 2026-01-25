import { Body, Controller, Post } from '@nestjs/common';
import { ApiBody, ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';
import { EventEmitter2 } from '@nestjs/event-emitter';

import { CreateUsernameDto } from './create-username.dto';
import { CreateUsernameResponseDto } from './create-username-response.dto';

@ApiTags('usernames')
@Controller('username')
export class UsernamesController {
  constructor(private eventEmitter: EventEmitter2) {}

  @Post()
  @ApiOperation({
    summary: 'Create a new username',
    description:
      'Registers a new username for a user. Username must be 3-32 characters, ' +
      'lowercase alphanumeric with underscores only.',
  })
  @ApiBody({
    type: CreateUsernameDto,
    description: 'Username creation payload',
  })
  @ApiResponse({
    status: 201,
    description: 'Username created successfully',
    type: CreateUsernameResponseDto,
  })
  @ApiResponse({
    status: 400,
    description: 'Invalid username format or validation failed',
  })
  createUsername(@Body() body: CreateUsernameDto): CreateUsernameResponseDto {
    // TODO: Implement actual username creation logic
    
    // Emit the "username_claimed" event as per Success Criteria
    // This is non-blocking and will be handled by stub in NotificationService
    this.eventEmitter.emit('username.claimed', {
      username: body.username,
      publicKey: body.publicKey,
      timestamp: new Date().toISOString(),
    });

    return { ok: true };
  }
}