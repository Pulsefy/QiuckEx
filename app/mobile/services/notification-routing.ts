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

function trackNotificationDeepLinkFailure(
  message: string,
  payload: unknown,
) {
  const payloadDetails = typeof payload === 'object' && payload !== null
    ? JSON.stringify(payload)
    : String(payload);

  console.warn('Notification deep link recovery:', message, payloadDetails);
}

function pushInboxFallback(router: Router, reason: string) {
  router.push({
    pathname: '/inbox',
    params: {
      source: 'notification_recovery',
      reason,
    },
  });
}

export function routeFromPushPayload(
  router: Router,
  payload: PushNotificationPayload,
) {
  if (payload.type === PUSH_NOTIFICATION_TYPES.transactionDetail) {
    if (!payload.transactionId) {
      trackNotificationDeepLinkFailure(
        'Missing transactionId for transaction detail notification',
        payload,
      );
      pushInboxFallback(router, 'missing_transaction_id');
      return;
    }

    router.push({
      pathname: '/transaction/[id]',
      params: {
        id: payload.transactionId,
        txHash: payload.txHash ?? payload.transactionId,
        amount: payload.amount ?? '0',
        asset: payload.asset ?? 'XLM',
        status: payload.status ?? 'Success',
        timestamp: new Date().toISOString(),
        source: 'notification',
        destination: 'notification',
      },
    });
    return;
  }

  if (payload.type === PUSH_NOTIFICATION_TYPES.escrowDetail) {
    if (!payload.escrowId) {
      trackNotificationDeepLinkFailure(
        'Missing escrowId for escrow detail notification',
        payload,
      );
      pushInboxFallback(router, 'missing_escrow_id');
      return;
    }

    router.push({
      pathname: '/escrow/[id]',
      params: { id: payload.escrowId, status: payload.status ?? 'open' },
    });
    return;
  }

  if (payload.type === PUSH_NOTIFICATION_TYPES.listingDetail) {
    if (!payload.listingId) {
      trackNotificationDeepLinkFailure(
        'Missing listingId for listing detail notification',
        payload,
      );
      pushInboxFallback(router, 'missing_listing_id');
      return;
    }

    router.push({
      pathname: '/listing/[id]',
      params: { id: payload.listingId, sellerId: payload.sellerId ?? 'unknown' },
    });
    return;
  }

  trackNotificationDeepLinkFailure(
    'Unsupported notification payload type',
    payload,
  );
  pushInboxFallback(router, 'unsupported_payload_type');
}

export function routeFromNotificationResponse(
  router: Router,
  response: NotificationResponse | null | undefined,
) {
  const payload = parsePushNotificationPayload(
    response?.notification?.request?.content?.data,
  );
  if (!payload) {
    trackNotificationDeepLinkFailure(
      'Malformed or incomplete push notification payload',
      response?.notification?.request?.content?.data,
    );
    pushInboxFallback(router, 'invalid_payload');
    return true;
  }

  routeFromPushPayload(router, payload);
  return true;
}
