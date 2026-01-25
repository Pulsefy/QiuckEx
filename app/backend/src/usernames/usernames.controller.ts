import { Body, Controller, Post } from '@nestjs/common';

import { CreateUsernameDto } from './create-username.dto';

@Controller('username')
export class UsernamesController {
  @Post()
  createUsername(@Body() body: CreateUsernameDto) {
    void body;
    return { ok: true };
  }
}
