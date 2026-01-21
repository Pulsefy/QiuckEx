import { Module } from '@nestjs/common';

import { UsernamesController } from './usernames.controller';

@Module({
  controllers: [UsernamesController],
})
export class UsernamesModule {}
