import type { NotificationPreference } from '../types/notification.types';
import type { NotificationPayload } from '../types/notification.types';

export function shouldSendNotification(
  pref: NotificationPreference,
  payload: NotificationPayload,
): boolean {
  if (!pref.enabled) return false;

  // Event filtering
  if (pref.events && !pref.events.includes(payload.eventType)) {
    return false;
  }

  // Amount filtering (if applicable)
  if (
    pref.minAmountStroops &&
    payload.amountStroops &&
    payload.amountStroops < pref.minAmountStroops
  ) {
    return false;
  }

  return true;
}