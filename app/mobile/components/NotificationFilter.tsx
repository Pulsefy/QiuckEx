import React from 'react';
import { View, Text, TouchableOpacity, StyleSheet } from 'react-native';
import { NotificationFilter as FilterType } from '../types/notification';

interface NotificationFilterProps {
  selectedFilter: FilterType;
  onFilterChange: (filter: FilterType) => void;
  unreadCount: number;
}

const filters: { label: string; value: FilterType }[] = [
  { label: 'All', value: 'all' },
  { label: 'Payments', value: 'payment' },
  { label: 'Escrows', value: 'escrow' },
  { label: 'System', value: 'system' },
];

export const NotificationFilter: React.FC<NotificationFilterProps> = ({
  selectedFilter,
  onFilterChange,
  unreadCount,
}) => {
  return (
    <View style={styles.container}>
      <View style={styles.filterContainer}>
        {filters.map((filter) => (
          <TouchableOpacity
            key={filter.value}
            style={[
              styles.filterButton,
              selectedFilter === filter.value && styles.filterButtonActive,
            ]}
            onPress={() => onFilterChange(filter.value)}
          >
            <Text
              style={[
                styles.filterText,
                selectedFilter === filter.value && styles.filterTextActive,
              ]}
            >
              {filter.label}
            </Text>
          </TouchableOpacity>
        ))}
      </View>
      <View style={styles.badgeContainer}>
        <Text style={styles.badgeText}>{unreadCount} unread</Text>
      </View>
    </View>
  );
};

const styles = StyleSheet.create({
  container: {
    paddingVertical: 12,
    backgroundColor: '#FFF',
    borderBottomWidth: 1,
    borderBottomColor: '#E5E5E5',
  },
  filterContainer: {
    flexDirection: 'row',
    paddingHorizontal: 16,
    marginBottom: 12,
  },
  filterButton: {
    paddingHorizontal: 16,
    paddingVertical: 8,
    borderRadius: 20,
    marginRight: 8,
    backgroundColor: '#F0F0F0',
  },
  filterButtonActive: {
    backgroundColor: '#007AFF',
  },
  filterText: {
    color: '#666',
    fontSize: 14,
  },
  filterTextActive: {
    color: '#FFF',
  },
  badgeContainer: {
    paddingHorizontal: 16,
  },
  badgeText: {
    color: '#666',
    fontSize: 12,
  },
});
