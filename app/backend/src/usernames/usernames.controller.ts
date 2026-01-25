import { Controller, Post } from '@nestjs/common';


@Controller('username')
export class UsernamesController {
  @Post()
  createUsername() {
    return { ok: true };
  }
}
