import React from 'react';
import { View, Text, StyleSheet } from 'react-native';
import { Picker } from '@react-native-picker/picker';
import { useTranslation } from 'react-i18next';
import { useTheme } from '../src/theme/ThemeContext';

export function LocaleSwitcher() {
  const { i18n } = useTranslation();
  const { theme } = useTheme();

  const changeLanguage = (lng: string) => {
    i18n.changeLanguage(lng);
  };

  return (
    <View style={[styles.card, { backgroundColor: theme.surface, borderColor: theme.border }]}>
      <Text style={[styles.label, { color: theme.textPrimary }]}>🌐 Language</Text>
      <Picker
        selectedValue={i18n.language}
        onValueChange={changeLanguage}
        style={{ color: theme.textPrimary }}
      >
        <Picker.Item label="English" value="en" />
        {/* Add more languages later */}
      </Picker>
    </View>
  );
}

const styles = StyleSheet.create({
  card: {
    borderRadius: 16,
    borderWidth: 1,
    padding: 16,
    marginBottom: 16,
  },
  label: {
    fontSize: 16,
    fontWeight: '600',
    marginBottom: 8,
  },
});