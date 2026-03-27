import React, { useEffect, useRef, useState } from "react";
import {
  Animated,
  Text,
  TouchableOpacity,
  View,
  StyleSheet,
} from "react-native";
import { useNotifications } from "./NotificationContext";

// Optional expo-av import will be attempted at runtime; if missing, sound is skipped.
let playSoundOnce: (() => Promise<void>) | undefined = undefined;
try {
  // eslint-disable-next-line @typescript-eslint/no-var-requires, global-require
  const { Audio } = require("expo-av");

  // Try a local asset first (mobile assets path). If it doesn't exist, fall back
  // to a small public chime hosted by Google Actions sounds as a safe fallback.
  const localSound = (() => {
    try {
      // correct relative path from this file to app/mobile/assets/sounds
      // components/notifications -> ../../assets/sounds
      // eslint-disable-next-line @typescript-eslint/no-var-requires, global-require
      return require("../../assets/sounds/notification.mp3");
    } catch (e) {
      return undefined;
    }
  })();

  playSoundOnce = async () => {
    try {
      const source = localSound ?? {
        uri: "https://actions.google.com/sounds/v1/cartoon/clang_and_wobble.ogg",
      };
      const { sound } = await Audio.Sound.createAsync(source as any);
      await sound.playAsync();
      sound.unloadAsync().catch(() => {});
    } catch (e) {
      // ignore playback errors
    }
  };
} catch (e) {
  // expo-av not installed — ignore sound
}

export const ToastNotification: React.FC = () => {
  const { notifications, unreadCount, soundEnabled } = useNotifications();
  const latest = notifications.find((n) => !n.read) ?? notifications[0];
  const anim = useRef(new Animated.Value(0)).current;
  const [visible, setVisible] = useState(false);

  useEffect(() => {
    if (!latest) return;
    setVisible(true);
    Animated.timing(anim, {
      toValue: 1,
      duration: 300,
      useNativeDriver: true,
    }).start();

    if (soundEnabled && playSoundOnce) {
      void playSoundOnce();
    }

    const t = setTimeout(() => {
      Animated.timing(anim, {
        toValue: 0,
        duration: 300,
        useNativeDriver: true,
      }).start(() => setVisible(false));
    }, 4000);

    return () => clearTimeout(t);
  }, [latest?.id]);

  if (!latest || !visible) return null;

  return (
    <Animated.View
      style={[
        styles.container,
        {
          transform: [
            {
              translateY: anim.interpolate({
                inputRange: [0, 1],
                outputRange: [-80, 0],
              }),
            },
          ],
        },
      ]}
    >
      <TouchableOpacity style={styles.toast} activeOpacity={0.9}>
        <Text style={styles.title}>💰 Payment Received</Text>
        <Text
          style={styles.body}
        >{`${latest.amount} ${latest.asset ?? ""} from ${shorten(latest.sender ?? "")}`}</Text>
      </TouchableOpacity>
    </Animated.View>
  );
};

function shorten(s: string) {
  if (!s) return "";
  if (s.length <= 10) return s;
  return `${s.slice(0, 6)}...${s.slice(-4)}`;
}

const styles = StyleSheet.create({
  container: {
    position: "absolute",
    top: 20,
    left: 0,
    right: 0,
    alignItems: "center",
    zIndex: 1000,
  },
  toast: {
    backgroundColor: "#111827",
    padding: 12,
    borderRadius: 10,
    minWidth: "80%",
    shadowColor: "#000",
    shadowOpacity: 0.2,
    shadowRadius: 8,
  },
  title: {
    color: "#fff",
    fontWeight: "700",
    marginBottom: 4,
  },
  body: {
    color: "#e5e7eb",
  },
});

export default ToastNotification;
