import { Module } from '@nestjs/common';
import { SentryModule as SentryNestModule } from '@sentry/nestjs/setup';
import { SentryService } from './sentry.service';

/**
 * SentryModule integrates Sentry error monitoring into the NestJS application.
 *
 * It re-exports the official @sentry/nestjs setup module (which registers the
 * global SentryGlobalFilter automatically) and provides a SentryService that
 * other modules can inject to capture errors and set user/request context.
 */
@Module({
  imports: [SentryNestModule.forRoot()],
  providers: [SentryService],
  exports: [SentryService],
})
export class SentryModule {}
