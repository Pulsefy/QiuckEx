import Constants from 'expo-constants';
import * as Notifications from 'expo-notifications';
import { useRouter } from 'expo-router';
import { useEffect } from 'react';
import { Platform } from 'react-native';
import { registerDeviceToken } from '../services/notifications';

Notifications.setNotificationHandler({
  handleNotification: async () => ({
    shouldShowAlert: true,
    shouldPlaySound: true,
    shouldSetBadge: false,
  }),
});

async function getPushTokenAsync() {
  if (!Constants.isDevice) return null;

  const { status: existingStatus } = await Notifications.getPermissionsAsync();
  let finalStatus = existingStatus;
  if (existingStatus !== 'granted') {
    const { status } = await Notifications.requestPermissionsAsync();
    finalStatus = status;
  }
  if (finalStatus !== 'granted') return null;

  try {
    const tokenData = await Notifications.getExpoPushTokenAsync();
    return tokenData.data;
  } catch (err) {
    console.warn('Error getting push token', err);
    return null;
  }
}

export default function useNotifications() {
  const router = useRouter();

  useEffect(() => {
    let responseListener: any;
    let receivedListener: any;

    (async () => {
      const token = await getPushTokenAsync();
      if (token) {
        // send to backend (no auth here; backend integration expected)
        registerDeviceToken({ expoPushToken: token, platform: Platform.OS });
      }
    })();

    receivedListener = Notifications.addNotificationReceivedListener((notification) => {
      // foreground notification handling logic can be placed here
      // e.g. update in-app state, show custom UI, etc.
      // console.log('Notification received', notification);
    });

    responseListener = Notifications.addNotificationResponseReceivedListener((response) => {
      const data = response.notification.request.content.data as any;
      if (!data) return;

      // If notification includes a transaction id, navigate to transactions screen
      if (data.txId) {
        router.push({ pathname: '/transactions', params: { txId: data.txId } });
      } else if (data.path) {
        // optional deep link path
        router.push(data.path);
      }
    });

    return () => {
      if (receivedListener) Notifications.removeNotificationSubscription(receivedListener);
      if (responseListener) Notifications.removeNotificationSubscription(responseListener);
    };
  }, [router]);
}
