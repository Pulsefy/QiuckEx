import React from 'react';
import { View, Text, TouchableOpacity, StyleSheet } from 'react-native';

export type ContactTag = 'Business' | 'Friends' | 'Favorites';

interface TagSelectorProps {
  selectedTags: ContactTag[];
  onToggleTag: (tag: ContactTag) => void;
}

const AVAILABLE_TAGS: ContactTag[] = ['Business', 'Friends', 'Favorites'];

export const TagSelector: React.FC<TagSelectorProps> = ({ selectedTags, onToggleTag }) => {
  return (
    <View style={styles.container}>
      <Text style={styles.label}>Tags (optional)</Text>
      <View style={styles.tagsContainer}>
        {AVAILABLE_TAGS.map((tag) => (
          <TouchableOpacity
            key={tag}
            onPress={() => onToggleTag(tag)}
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
    </View>
  );
};

const styles = StyleSheet.create({
  container: {
    marginBottom: 16,
  },
  label: {
    fontSize: 14,
    fontWeight: '600',
    marginBottom: 8,
    color: '#666',
  },
  tagsContainer: {
    flexDirection: 'row',
    flexWrap: 'wrap',
    gap: 8,
  },
  tag: {
    paddingHorizontal: 16,
    paddingVertical: 8,
    borderRadius: 20,
    backgroundColor: '#E5E5E5',
    borderWidth: 1,
    borderColor: 'transparent',
  },
  tagSelected: {
    backgroundColor: '#007AFF',
    borderColor: '#007AFF',
  },
  tagText: {
    color: '#000',
    fontSize: 14,
  },
  tagTextSelected: {
    color: '#FFF',
  },
});
