import React, { useCallback, useEffect, useRef, useState } from "react";
import {
  ActivityIndicator,
  Pressable,
  StyleSheet,
  Text,
  View,
} from "react-native";
import { useTheme } from "../../src/theme/ThemeContext";

interface AppLockOverlayProps {
  visible: boolean;
  onUnlock: () => Promise<boolean>;
}

export function AppLockOverlay({ visible, onUnlock }: AppLockOverlayProps) {
  const { theme } = useTheme();
  const [unlocking, setUnlocking] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const attemptedAutoUnlock = useRef(false);

  const unlock = useCallback(async () => {
    setUnlocking(true);
    setErrorMessage(null);

    const authenticated = await onUnlock();
    if (!authenticated) {
      setErrorMessage("Authentication was not completed. Please try again.");
    }

    setUnlocking(false);
  }, [onUnlock]);

  useEffect(() => {
    if (!visible) {
      attemptedAutoUnlock.current = false;
      setErrorMessage(null);
      return;
    }

    if (attemptedAutoUnlock.current) return;
    attemptedAutoUnlock.current = true;

    unlock();
  }, [unlock, visible]);

  if (!visible) return null;

  return (
    <View style={[styles.overlay, { backgroundColor: theme.overlayBg }]}>
      <View style={[styles.card, { backgroundColor: theme.surfaceElevated }]}>
        <Text style={[styles.title, { color: theme.textPrimary }]}>QuickEx Security Lock</Text>
        <Text style={[styles.body, { color: theme.textSecondary }]}>
          Use biometrics or your fallback PIN to continue.
        </Text>

        {unlocking ? <ActivityIndicator size="small" color={theme.primary} /> : null}
        {errorMessage ? <Text style={[styles.error, { color: theme.status.error }]}>{errorMessage}</Text> : null}

        <Pressable style={[styles.button, { backgroundColor: theme.buttonPrimaryBg }]} onPress={unlock} disabled={unlocking}>
          <Text style={[styles.buttonText, { color: theme.buttonPrimaryText }]}>Unlock App</Text>
        </Pressable>
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  overlay: {
    ...StyleSheet.absoluteFillObject,
    justifyContent: "center",
    alignItems: "center",
    padding: 24,
    zIndex: 30,
  },
  card: {
    width: "100%",
    maxWidth: 380,
    borderRadius: 20,
    padding: 24,
    alignItems: "center",
  },
  title: {
    fontSize: 24,
    fontWeight: "800",
    marginBottom: 8,
    textAlign: "center",
  },
  body: {
    fontSize: 15,
    textAlign: "center",
    lineHeight: 22,
    marginBottom: 16,
  },
  error: {
    marginTop: 10,
    marginBottom: 8,
    fontSize: 13,
  },
  button: {
    marginTop: 8,
    borderRadius: 12,
    width: "100%",
    alignItems: "center",
    paddingVertical: 14,
  },
  buttonText: {
    fontWeight: "700",
    fontSize: 16,
  },
});
