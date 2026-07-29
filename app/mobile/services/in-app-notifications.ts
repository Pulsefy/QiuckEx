import Constants from "expo-constants";

/**
 * Low-level client for backend in-app notification read-state APIs.
 * Set EXPO_PUBLIC_API_URL in your .env file.
 */
const API_BASE_URL =
  (Constants.expoConfig?.extra?.apiUrl as string | undefined) ??
  process.env["EXPO_PUBLIC_API_URL"] ??
  "http://localhost:3000";

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

export interface FetchInAppOptions {
  page?: number;
  limit?: number;
}

type SupabaseListResponse = {
  data?: InAppNotificationDto[] | null;
  error?: { message?: string } | null;
};

function getApiBaseUrl() {
  return API_BASE_URL.replace(/\/$/, "");
}

async function requestJson<T>(
  path: string,
  init?: RequestInit,
): Promise<T> {
  let response: Response;
  try {
    response = await fetch(`${getApiBaseUrl()}${path}`, {
      ...init,
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
        ...(init?.headers ?? {}),
      },
    });
  } catch {
    throw new Error(
      "Network request failed. Check your connection and try again.",
    );
  }

  if (!response.ok) {
    let message = `Server error (${response.status})`;
    try {
      const body = (await response.json()) as { message?: string };
      if (body.message) message = body.message;
    } catch {
      // keep status-code message
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
  payload: InAppNotificationDto[] | SupabaseListResponse | null | undefined,
): InAppNotificationDto[] {
  if (!payload) return [];
  if (Array.isArray(payload)) return payload;
  if (Array.isArray(payload.data)) return payload.data;
  if (payload.error?.message) {
    throw new Error(payload.error.message);
  }
  return [];
}

/**
 * Fetches paginated in-app notifications for a Stellar account.
 */
export async function fetchInAppNotifications(
  publicKey: string,
  options: FetchInAppOptions = {},
): Promise<InAppNotificationDto[]> {
  const { page = 1, limit = 50 } = options;
  const params = new URLSearchParams({
    publicKey,
    page: String(page),
    limit: String(limit),
  });

  const payload = await requestJson<
    InAppNotificationDto[] | SupabaseListResponse
  >(`/notifications/in-app?${params.toString()}`);

  return unwrapList(payload);
}

/**
 * Marks a single in-app notification as read on the backend.
 */
export async function markInAppNotificationRead(id: string): Promise<void> {
  await requestJson(`/notifications/in-app/${encodeURIComponent(id)}/read`, {
    method: "POST",
  });
}

/**
 * Marks all in-app notifications as read for a Stellar account.
 */
export async function markAllInAppNotificationsRead(
  publicKey: string,
): Promise<void> {
  const params = new URLSearchParams({ publicKey });
  await requestJson(`/notifications/in-app/read-all?${params.toString()}`, {
    method: "POST",
  });
}

/**
 * Derives unread count from a fetched in-app notification list.
 */
export function countUnreadInAppNotifications(
  notifications: Array<{ read: boolean }>,
): number {
  return notifications.filter((notification) => !notification.read).length;
}
