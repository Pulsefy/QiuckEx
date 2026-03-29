import { Injectable, Logger } from '@nestjs/common';
import * as Sentry from '@sentry/node';

/**
 * SentryService provides a clean, injectable interface to Sentry's
 * error-reporting and context-setting capabilities.
 *
 * Usage:
 *   constructor(private readonly sentry: SentryService) {}
 *
 *   this.sentry.captureException(error, { orderId: '123' });
 *   this.sentry.captureMessage('Horizon API unreachable', 'fatal');
 */
@Injectable()
export class SentryService {
  private readonly logger = new Logger(SentryService.name);

  /**
   * Check whether Sentry is initialised (i.e. a DSN was provided).
   */
  get isEnabled(): boolean {
    return !!Sentry.getClient();
  }

  /**
   * Capture an exception and send it to Sentry with optional extra context.
   *
   * @param exception  The error to report
   * @param extras     Additional key-value pairs to attach (no sensitive data!)
   */
  captureException(
    exception: unknown,
    extras?: Record<string, unknown>,
  ): string | undefined {
    if (!this.isEnabled) {
      this.logger.warn(
        'Sentry is not initialised — exception not reported remotely.',
      );
      return undefined;
    }

    return Sentry.captureException(exception, (scope) => {
      if (extras) {
        scope.setExtras(extras);
      }
      return scope;
    });
  }

  /**
   * Capture an informational or warning message.
   *
   * @param message  Human-readable description of the event
   * @param level    Sentry severity level
   * @param extras   Additional context
   */
  captureMessage(
    message: string,
    level: Sentry.SeverityLevel = 'info',
    extras?: Record<string, unknown>,
  ): string | undefined {
    if (!this.isEnabled) {
      this.logger.warn(
        'Sentry is not initialised — message not reported remotely.',
      );
      return undefined;
    }

    return Sentry.captureMessage(message, (scope) => {
      scope.setLevel(level);
      if (extras) {
        scope.setExtras(extras);
      }
      return scope;
    });
  }

  /**
   * Set user context on the current Sentry scope.
   * Call this after authentication to tag all subsequent events.
   */
  setUser(user: { id?: string; wallet?: string; username?: string }): void {
    Sentry.setUser({
      id: user.id,
      username: user.username,
      // Store wallet as custom data (not email/ip for privacy)
      ...(user.wallet ? { wallet: user.wallet } : {}),
    } as Sentry.User);
  }

  /**
   * Clear user context (e.g. on logout / request end).
   */
  clearUser(): void {
    Sentry.setUser(null);
  }

  /**
   * Add a custom breadcrumb to the current Sentry scope.
   * Useful for tracing business-logic steps (e.g. "started Stellar payment").
   */
  addBreadcrumb(breadcrumb: {
    category: string;
    message: string;
    level?: Sentry.SeverityLevel;
    data?: Record<string, unknown>;
  }): void {
    Sentry.addBreadcrumb({
      category: breadcrumb.category,
      message: breadcrumb.message,
      level: breadcrumb.level || 'info',
      data: breadcrumb.data,
    });
  }

  /**
   * Set a custom tag on the current scope.
   * Tags are indexed and searchable in the Sentry dashboard.
   */
  setTag(key: string, value: string): void {
    Sentry.setTag(key, value);
  }

  /**
   * Set extra context on the current scope.
   */
  setExtra(key: string, value: unknown): void {
    Sentry.setExtra(key, value);
  }
}
