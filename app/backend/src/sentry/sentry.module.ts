import { Module } from '@nestjs/common';
import { SentryModule as SentryNestModule } from '@sentry/nestjs/setup';
import { SentryService } from './sentry.service';
import { SentryTracingService } from './sentry-tracing.service';

/**
 * SentryModule integrates Sentry error monitoring and performance tracing into
 * the NestJS application.
 *
 * It re-exports the official @sentry/nestjs setup module (which registers the
 * global SentryGlobalFilter automatically) and provides:
 * - SentryService   — capture errors, set user/request context
 * - SentryTracingService — create child spans for Horizon, Soroban, cache, and
 *   compose/simulate/submit transaction paths
 */
@Module({
  imports: [SentryNestModule.forRoot()],
  providers: [SentryService, SentryTracingService],
  exports: [SentryService, SentryTracingService],
})
export class SentryModule {}
