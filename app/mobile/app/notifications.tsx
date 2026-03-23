import AsyncStorage from '@react-native-async-storage/async-storage';
import React, { useEffect, useState } from 'react';
import { Button, StyleSheet, Switch, Text, View } from 'react-native';
import useNotifications from '../hooks/useNotifications';

const NOTIF_PREFS_KEY = 'notif_prefs_v1';

export default function NotificationsSettings() {
  useNotifications();
  const [incomingPayments, setIncomingPayments] = useState(true);
  const [escrowUpdates, setEscrowUpdates] = useState(true);

  useEffect(() => {
    (async () => {
      try {
        const raw = await AsyncStorage.getItem(NOTIF_PREFS_KEY);
        if (raw) {
          const prefs = JSON.parse(raw);
          setIncomingPayments(Boolean(prefs.incomingPayments));
          setEscrowUpdates(Boolean(prefs.escrowUpdates));
        }
      } catch (err) {
        // ignore
      }
    })();
  }, []);

  async function savePrefs() {
    const prefs = { incomingPayments, escrowUpdates };
    await AsyncStorage.setItem(NOTIF_PREFS_KEY, JSON.stringify(prefs));
  }

  return (
    <View style={styles.container}>
      <Text style={styles.title}>Notifications</Text>

      <View style={styles.row}>
        <Text>Incoming payments</Text>
        <Switch value={incomingPayments} onValueChange={setIncomingPayments} />
      </View>

      <View style={styles.row}>
        <Text>Escrow updates</Text>
        <Switch value={escrowUpdates} onValueChange={setEscrowUpdates} />
      </View>

      <Button title="Save" onPress={savePrefs} />
    </View>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, padding: 16 },
  title: { fontSize: 20, fontWeight: '600', marginBottom: 16 },
  row: { flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center', marginVertical: 12 },
});
