import * as Notifications from "expo-notifications";

import {
  PUSH_NOTIFICATION_TYPES,
  type PushNotificationPayload,
} from "../types/push-notification";

let handlerConfigured = false;

export function configureNotificationSimulator() {
  if (handlerConfigured) return;
  handlerConfigured = true;

  Notifications.setNotificationHandler({
    handleNotification: async () => ({
      shouldShowBanner: true,
      shouldShowList: true,
      shouldPlaySound: false,
      shouldSetBadge: false,
    }),
  });
}

export async function scheduleNotificationSimulation(
  payload: PushNotificationPayload,
) {
  configureNotificationSimulator();
  const permissions = await Notifications.getPermissionsAsync();
  if (!permissions.granted) {
    const requested = await Notifications.requestPermissionsAsync();
    if (!requested.granted) return;
  }

  await Notifications.scheduleNotificationAsync({
    content: {
      title: notificationTitle(payload),
      body: notificationBody(payload),
      data: payload,
    },
    trigger: null,
  });
}

function notificationTitle(payload: PushNotificationPayload): string {
  if (payload.type === PUSH_NOTIFICATION_TYPES.transactionDetail) {
    return "Transaction update";
  }
  if (payload.type === PUSH_NOTIFICATION_TYPES.escrowDetail) {
    return "Escrow update";
  }
  return "Listing update";
}

function notificationBody(payload: PushNotificationPayload): string {
  if (payload.type === PUSH_NOTIFICATION_TYPES.transactionDetail) {
    return `Open transaction ${payload.transactionId}`;
  }
  if (payload.type === PUSH_NOTIFICATION_TYPES.escrowDetail) {
    return `Open escrow ${payload.escrowId}`;
  }
  return `Open listing ${payload.listingId}`;
}
