export interface Contact {
  id: string; // uuid
  address: string;
  nickname: string;
  tags?: string[]; // Add tags array (Business, Friends, Favorites)
  createdAt: number;
  updatedAt: number;
}

// Define available tags
export type ContactTag = 'Business' | 'Friends' | 'Favorites';

export const AVAILABLE_TAGS: ContactTag[] = ['Business', 'Friends', 'Favorites'];
