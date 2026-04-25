import React, { useEffect, useRef, useState } from "react";
import {
  Animated,
  StyleSheet,
  Text,
  TouchableOpacity,
} from "react-native";

import { useTheme } from "../../src/theme/ThemeContext";
import { useNotifications } from "./NotificationContext";

let playSoundOnce: (() => Promise<void>) | undefined;
try {
  // eslint-disable-next-line @typescript-eslint/no-var-requires, global-require
  const { Audio } = require("expo-av");

  const localSound = (() => {
    try {
      // eslint-disable-next-line @typescript-eslint/no-var-requires, global-require
      return require("../../assets/sounds/notification.mp3");
    } catch {
      return undefined;
    }
  })();

  playSoundOnce = async () => {
    try {
      const source = localSound ?? {
        uri: "https://actions.google.com/sounds/v1/cartoon/clang_and_wobble.ogg",
      };
      const { sound } = await Audio.Sound.createAsync(source as never);
      await sound.playAsync();
      sound.unloadAsync().catch(() => {});
    } catch {
      // Best-effort sound playback only.
    }
  };
} catch {
  playSoundOnce = undefined;
}

export const ToastNotification: React.FC = () => {
  const { notifications, soundEnabled } = useNotifications();
  const { theme } = useTheme();
  const latest = notifications.find((item) => !item.read) ?? notifications[0];
  const anim = useRef(new Animated.Value(0)).current;
  const [visible, setVisible] = useState(false);

  useEffect(() => {
    if (!latest || latest.read) return;

    setVisible(true);
    Animated.timing(anim, {
      toValue: 1,
      duration: 300,
      useNativeDriver: true,
    }).start();

    if (soundEnabled && playSoundOnce) {
      void playSoundOnce();
    }

    const timeoutId = setTimeout(() => {
      Animated.timing(anim, {
        toValue: 0,
        duration: 300,
        useNativeDriver: true,
      }).start(() => setVisible(false));
    }, 4000);

    return () => clearTimeout(timeoutId);
  }, [anim, latest, soundEnabled]);

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
      <TouchableOpacity
        style={[styles.toast, { backgroundColor: theme.buttonPrimaryBg }]}
        activeOpacity={0.9}
      >
        <Text style={[styles.title, { color: theme.buttonPrimaryText }]}>
          {latest.direction === "outgoing" ? "Payment Sent" : "Payment Received"}
        </Text>
        <Text style={[styles.body, { color: theme.buttonPrimaryText }]}>
          {`${latest.amount} ${latest.asset ?? ""} ${
            latest.direction === "outgoing" ? "to" : "from"
          } ${shorten(latest.sender ?? "")}`}
        </Text>
      </TouchableOpacity>
    </Animated.View>
  );
};

function shorten(value: string) {
  if (!value) return "";
  if (value.length <= 10) return value;
  return `${value.slice(0, 6)}...${value.slice(-4)}`;
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
    padding: 12,
    borderRadius: 10,
    minWidth: "80%",
    shadowColor: "#000",
    shadowOpacity: 0.2,
    shadowRadius: 8,
  },
  title: {
    fontWeight: "700",
    marginBottom: 4,
  },
  body: {},
});

export default ToastNotification;
