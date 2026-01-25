import { Body, Controller, Post, Version } from '@nestjs/common';

import { CreateUsernameDto } from './create-username.dto';

@Controller('username')
export class UsernamesController {
  @Post()
  @Version('1')
  createUsername(@Body() _body: CreateUsernameDto) {
    return { ok: true };
  }
}
