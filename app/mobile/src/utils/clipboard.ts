import * as Clipboard from 'expo-clipboard';

/**
 * Copy text to clipboard with feedback
 */
export async function copyToClipboard(text: string, onSuccess?: () => void): Promise<boolean> {
  try {
    await Clipboard.setStringAsync(text);
    onSuccess?.();
    return true;
  } catch (error) {
    console.error('Failed to copy to clipboard:', error);
    return false;
  }
}

/**
 * Format metadata object as a readable string for sharing
 */
export function formatMetadataForSharing(metadata: Record<string, string>): string {
  return Object.entries(metadata)
    .map(([key, value]) => `${key}: ${value}`)
    .join('\n');
}
