/** Retry delays in milliseconds: 1m, 5m, 15m, 1h, 6h (exponential backoff). */
export const WEBHOOK_RETRY_DELAYS_MS = [
  60_000,
  300_000,
  900_000,
  3_600_000,
  21_600_000,
] as const;

/** Total delivery attempts (1 initial + retries). */
export const WEBHOOK_MAX_DELIVERY_ATTEMPTS =
  WEBHOOK_RETRY_DELAYS_MS.length + 1;

export function computeWebhookNextRetryAt(
  attempts: number,
  lastFailedAt: string | Date,
): Date | null {
  if (attempts <= 0 || attempts >= WEBHOOK_MAX_DELIVERY_ATTEMPTS) {
    return null;
  }

  const delayMs =
    WEBHOOK_RETRY_DELAYS_MS[attempts - 1] ??
    WEBHOOK_RETRY_DELAYS_MS[WEBHOOK_RETRY_DELAYS_MS.length - 1];
  const base =
    lastFailedAt instanceof Date
      ? lastFailedAt.getTime()
      : new Date(lastFailedAt).getTime();

  return new Date(base + delayMs);
}
