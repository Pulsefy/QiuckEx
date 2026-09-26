import { getQuickexApiBase } from "@/lib/api";
import { resolvePublicKey } from "@/lib/publicKey";
import type { NotificationCategory, StoredNotification } from "@/lib/notifications";

/**
 * Backend in-app notification shape returned by `GET /notifications/in-app`.
 * Mirrors `InAppNotification` in the backend notifications module and the
 * mobile `InAppNotificationDto`.
 */
export interface InAppNotificationDto {
  id: string;
  publicKey: string;
  eventType: string;
  eventId: string;
  title: string;
  body: string;
  read: boolean;
  metadata?: Record<string, unknown> | null;
  createdAt: string;
}

export interface FetchNotificationsResult {
  notifications: StoredNotification[];
  /** True when the backend could not be reached and no live data is available. */
  degraded: boolean;
}

const CATEGORY_BY_EVENT_PREFIX: Array<{
  match: (eventType: string) => boolean;
  category: NotificationCategory;
}> = [
  {
    match: (eventType) => eventType.startsWith("payment"),
    category: "payments",
  },
  {
    match: (eventType) => eventType.startsWith("escrow"),
    category: "escrows",
  },
];

/**
 * Maps a backend `eventType` onto the frontend notification categories used by
 * the category filter UI. Unknown event types fall back to "system" so that
 * server-generated notifications always render.
 */
export function categoryForEventType(eventType: string): NotificationCategory {
  const normalized = eventType.toLowerCase();
  const match = CATEGORY_BY_EVENT_PREFIX.find((entry) => entry.match(normalized));
  return match?.category ?? "system";
}

function readMetadataString(
  metadata: Record<string, unknown> | null | undefined,
  key: string,
): string | undefined {
  const value = metadata?.[key];
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

/**
 * Converts a backend in-app notification into the `StoredNotification` shape
 * consumed by the notification center UI.
 */
export function mapInAppNotification(
  notification: InAppNotificationDto,
): StoredNotification {
  const href =
    readMetadataString(notification.metadata, "href") ??
    readMetadataString(notification.metadata, "url") ??
    "/notifications";
  const actionLabel =
    readMetadataString(notification.metadata, "actionLabel") ??
    "Open notification";

  return {
    id: notification.id,
    category: categoryForEventType(notification.eventType),
    title: notification.title,
    description: notification.body,
    href,
    actionLabel,
    createdAt: notification.createdAt,
    readAt: notification.read ? notification.createdAt : null,
  };
}

async function requestJson<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${getQuickexApiBase()}${path}`, {
    ...init,
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json",
      ...(init?.headers ?? {}),
    },
  });

  if (!response.ok) {
    let message = `Server error (${response.status})`;
    try {
      const body = (await response.json()) as { message?: string };
      if (body.message) message = body.message;
    } catch {
      // keep the status-code message
    }
    throw new Error(message);
  }

  if (response.status === 204) {
    return undefined as T;
  }

  const text = await response.text();
  if (!text) {
    return undefined as T;
  }

  return JSON.parse(text) as T;
}

function unwrapList(
  payload: InAppNotificationDto[] | { data?: InAppNotificationDto[] | null } | null | undefined,
): InAppNotificationDto[] {
  if (!payload) return [];
  if (Array.isArray(payload)) return payload;
  if (Array.isArray(payload.data)) return payload.data;
  return [];
}

/**
 * Fetches the current user's in-app notifications from the backend.
 *
 * On failure the caller receives an empty list with `degraded: true` so the UI
 * can render a visible degraded-state indicator instead of a hardcoded seed.
 */
export async function fetchNotifications(
  options: { page?: number; limit?: number } = {},
): Promise<FetchNotificationsResult> {
  const { page = 1, limit = 50 } = options;
  const publicKey = resolvePublicKey();
  const params = new URLSearchParams({
    publicKey,
    page: String(page),
    limit: String(limit),
  });

  try {
    const payload = await requestJson<
      InAppNotificationDto[] | { data?: InAppNotificationDto[] | null }
    >(`/notifications/in-app?${params.toString()}`);

    return {
      notifications: unwrapList(payload).map(mapInAppNotification),
      degraded: false,
    };
  } catch (error) {
    console.warn(
      "Notification center: backend unavailable, showing degraded state:",
      error,
    );
    return { notifications: [], degraded: true };
  }
}

/**
 * Marks a single notification as read on the backend.
 * Throws when the backend call fails so callers can surface the error.
 */
export async function markNotificationRead(id: string): Promise<void> {
  await requestJson(`/notifications/in-app/${encodeURIComponent(id)}/read`, {
    method: "POST",
  });
}

/**
 * Marks every notification as read on the backend.
 * Throws when the backend call fails so callers can surface the error.
 */
export async function markAllNotificationsRead(): Promise<void> {
  const params = new URLSearchParams({ publicKey: resolvePublicKey() });
  await requestJson(`/notifications/in-app/read-all?${params.toString()}`, {
    method: "POST",
  });
}
