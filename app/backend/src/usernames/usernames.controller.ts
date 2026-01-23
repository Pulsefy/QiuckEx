import { Body, Controller, Post } from '@nestjs/common';

import { CreateUsernameDto } from './create-username.dto';

@Controller('username')
export class UsernamesController {
  @Post()
  createUsername(@Body() _body: CreateUsernameDto) {
    return { ok: true };
  }
}
