import type { Router } from "expo-router";
import type { NotificationResponse } from "expo-notifications";

import {
  PUSH_NOTIFICATION_TYPES,
  type PushNotificationPayload,
} from "../types/push-notification";

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0;
}

export function parsePushNotificationPayload(
  value: unknown,
): PushNotificationPayload | null {
  if (!isObject(value) || !isNonEmptyString(value.type)) return null;

  if (
    value.type === PUSH_NOTIFICATION_TYPES.transactionDetail &&
    isNonEmptyString(value.transactionId)
  ) {
    return {
      type: PUSH_NOTIFICATION_TYPES.transactionDetail,
      transactionId: value.transactionId,
      txHash: isNonEmptyString(value.txHash) ? value.txHash : undefined,
      amount: isNonEmptyString(value.amount) ? value.amount : undefined,
      asset: isNonEmptyString(value.asset) ? value.asset : undefined,
      status: isNonEmptyString(value.status) ? value.status : undefined,
    };
  }

  if (
    value.type === PUSH_NOTIFICATION_TYPES.escrowDetail &&
    isNonEmptyString(value.escrowId)
  ) {
    return {
      type: PUSH_NOTIFICATION_TYPES.escrowDetail,
      escrowId: value.escrowId,
      status: isNonEmptyString(value.status) ? value.status : undefined,
    };
  }

  if (
    value.type === PUSH_NOTIFICATION_TYPES.listingDetail &&
    isNonEmptyString(value.listingId)
  ) {
    return {
      type: PUSH_NOTIFICATION_TYPES.listingDetail,
      listingId: value.listingId,
      sellerId: isNonEmptyString(value.sellerId) ? value.sellerId : undefined,
    };
  }

  return null;
}

export function routeFromPushPayload(
  router: Router,
  payload: PushNotificationPayload,
) {
  if (payload.type === PUSH_NOTIFICATION_TYPES.transactionDetail) {
    router.push({
      pathname: "/transaction/[id]",
      params: {
        id: payload.transactionId,
        txHash: payload.txHash ?? payload.transactionId,
        amount: payload.amount ?? "0",
        asset: payload.asset ?? "XLM",
        status: payload.status ?? "Success",
        timestamp: new Date().toISOString(),
        source: "notification",
        destination: "notification",
      },
    });
    return;
  }

  if (payload.type === PUSH_NOTIFICATION_TYPES.escrowDetail) {
    router.push({
      pathname: "/escrow/[id]",
      params: { id: payload.escrowId, status: payload.status ?? "open" },
    });
    return;
  }

  router.push({
    pathname: "/listing/[id]",
    params: { id: payload.listingId, sellerId: payload.sellerId ?? "unknown" },
  });
}

export function routeFromNotificationResponse(
  router: Router,
  response: NotificationResponse | null | undefined,
) {
  const payload = parsePushNotificationPayload(
    response?.notification?.request?.content?.data,
  );
  if (!payload) return false;
  routeFromPushPayload(router, payload);
  return true;
}
