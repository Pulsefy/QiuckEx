import React, { useCallback, useEffect, useRef, useState } from "react";
import {
  ActivityIndicator,
  Pressable,
  StyleSheet,
  Text,
  View,
} from "react-native";

interface AppLockOverlayProps {
  visible: boolean;
  onUnlock: () => Promise<boolean>;
}

export function AppLockOverlay({ visible, onUnlock }: AppLockOverlayProps) {
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
    <View style={styles.overlay}>
      <View style={styles.card}>
        <Text style={styles.title}>QuickEx Security Lock</Text>
        <Text style={styles.body}>
          Use biometrics or your fallback PIN to continue.
        </Text>

        {unlocking ? <ActivityIndicator size="small" color="#111827" /> : null}
        {errorMessage ? <Text style={styles.error}>{errorMessage}</Text> : null}

        <Pressable style={styles.button} onPress={unlock} disabled={unlocking}>
          <Text style={styles.buttonText}>Unlock App</Text>
        </Pressable>
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  overlay: {
    ...StyleSheet.absoluteFillObject,
    backgroundColor: "rgba(17, 24, 39, 0.74)",
    justifyContent: "center",
    alignItems: "center",
    padding: 24,
    zIndex: 30,
  },
  card: {
    width: "100%",
    maxWidth: 380,
    borderRadius: 20,
    backgroundColor: "#fff",
    padding: 24,
    alignItems: "center",
  },
  title: {
    fontSize: 24,
    fontWeight: "800",
    color: "#111827",
    marginBottom: 8,
    textAlign: "center",
  },
  body: {
    color: "#6B7280",
    fontSize: 15,
    textAlign: "center",
    lineHeight: 22,
    marginBottom: 16,
  },
  error: {
    color: "#B91C1C",
    marginTop: 10,
    marginBottom: 8,
    fontSize: 13,
  },
  button: {
    marginTop: 8,
    backgroundColor: "#111827",
    borderRadius: 12,
    width: "100%",
    alignItems: "center",
    paddingVertical: 14,
  },
  buttonText: {
    color: "#fff",
    fontWeight: "700",
    fontSize: 16,
  },
});
