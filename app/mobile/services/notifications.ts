import { Platform } from 'react-native';

export type DeviceToken = {
  expoPushToken?: string;
  platform?: string;
};

/**
 * Send device token to QuickEx backend so server can push notifications.
 * Replace BACKEND_URL with your backend endpoint or set the env var.
 */
export async function registerDeviceToken(token: DeviceToken, authToken?: string) {
  try {
    const BACKEND_URL = process.env.BACKEND_URL || 'https://api.quickex.example';
    await fetch(`${BACKEND_URL}/notifications/register`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(authToken ? { Authorization: `Bearer ${authToken}` } : {}),
      },
      body: JSON.stringify({ token, platform: Platform.OS }),
    });
  } catch (err) {
    // swallow network errors for now; calling code can surface if needed
    console.warn('Failed to register device token', err);
  }
}
