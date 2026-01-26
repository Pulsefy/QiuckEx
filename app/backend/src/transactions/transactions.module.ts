import { Module } from '@nestjs/common';
import { TransactionsController } from './transactions.controller';
import { HorizonService } from './horizon.service';
import { AppConfigModule } from '../config';

@Module({
    imports: [AppConfigModule],
    controllers: [TransactionsController],
    providers: [HorizonService],
    exports: [HorizonService],
})
export class TransactionsModule { }
