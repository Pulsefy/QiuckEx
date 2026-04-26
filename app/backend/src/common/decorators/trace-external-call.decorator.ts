import { Logger } from '@nestjs/common';
import { MetricsService } from '../../metrics/metrics.service';

/**
 * Decorator to trace external API calls with timing and error tracking.
 * Automatically records metrics and logs for observability.
 *
 * Usage:
 * @TraceExternalCall('horizon', 'loadAccount')
 * async loadAccount(address: string) { ... }
 *
 * @TraceExternalCall('webhook', 'send')
 * async sendWebhook(url: string, payload: unknown) { ... }
 */
export function TraceExternalCall(service: string, operation: string) {
  return function (
    target: Record<string, unknown>,
    propertyKey: string,
    descriptor: PropertyDescriptor,
  ) {
    const originalMethod = descriptor.value;
    const logger = new Logger(`${service}.${operation}`);

    descriptor.value = async function (...args: unknown[]) {
      const metricsService: MetricsService = (this as Record<string, unknown>).metricsService as MetricsService;
      const startTime = Date.now();
      const correlationId = (this as Record<string, unknown>).correlationId as string || 'N/A';

      logger.debug(
        JSON.stringify({
          correlationId,
          service,
          operation,
          status: 'started',
        }),
      );

      try {
        const result = await originalMethod.apply(this, args);
        const duration = (Date.now() - startTime) / 1000; // Convert to seconds

        logger.debug(
          JSON.stringify({
            correlationId,
            service,
            operation,
            status: 'success',
            duration: `${duration}s`,
          }),
        );

        if (metricsService) {
          metricsService.recordExternalCall(service, operation, duration);
        }

        return result;
      } catch (error) {
        const duration = (Date.now() - startTime) / 1000;
        const errorType = error instanceof Error ? error.constructor.name : 'UnknownError';

        logger.error(
          JSON.stringify({
            correlationId,
            service,
            operation,
            status: 'error',
            duration: `${duration}s`,
            errorType,
            errorMessage: error instanceof Error ? error.message : String(error),
          }),
        );

        if (metricsService) {
          metricsService.recordExternalCall(service, operation, duration);
          metricsService.recordError(service, errorType);
        }

        throw error;
      }
    };

    return descriptor;
  };
}
