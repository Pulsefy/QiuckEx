import React from 'react';
import { View, Text, TouchableOpacity, ScrollView, StyleSheet } from 'react-native';

export type ContactTag = 'Business' | 'Friends' | 'Favorites';

interface TagFilterProps {
  selectedTags: ContactTag[];
  onTagPress: (tag: ContactTag) => void;
}

const AVAILABLE_TAGS: ContactTag[] = ['Business', 'Friends', 'Favorites'];

export const TagFilter: React.FC<TagFilterProps> = ({ selectedTags, onTagPress }) => {
  return (
    <ScrollView horizontal showsHorizontalScrollIndicator={false} style={styles.container}>
      <View style={styles.tagsContainer}>
        {AVAILABLE_TAGS.map((tag) => (
          <TouchableOpacity
            key={tag}
            onPress={() => onTagPress(tag)}
            style={[
              styles.tag,
              selectedTags.includes(tag) && styles.tagSelected,
            ]}
          >
            <Text style={[
              styles.tagText,
              selectedTags.includes(tag) && styles.tagTextSelected,
            ]}>
              {tag}
            </Text>
          </TouchableOpacity>
        ))}
      </View>
    </ScrollView>
  );
};

const styles = StyleSheet.create({
  container: {
    maxHeight: 60,
  },
  tagsContainer: {
    flexDirection: 'row',
    paddingHorizontal: 16,
    paddingVertical: 8,
  },
  tag: {
    paddingHorizontal: 16,
    paddingVertical: 8,
    borderRadius: 20,
    backgroundColor: '#E5E5E5',
    marginRight: 8,
  },
  tagSelected: {
    backgroundColor: '#007AFF',
  },
  tagText: {
    color: '#000',
    fontSize: 14,
  },
  tagTextSelected: {
    color: '#FFF',
  },
});
