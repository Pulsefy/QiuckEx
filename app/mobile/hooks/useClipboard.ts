import { useCallback, useState } from 'react';
import { Clipboard, ToastAndroid, Platform } from 'react-native';
import * as ClipboardExpo from 'expo-clipboard';

interface UseClipboardReturn {
  copied: boolean;
  copy: (text: string, label?: string) => Promise<void>;
}

/**
 * Cross-platform clipboard hook with toast feedback
 */
export function useClipboard(): UseClipboardReturn {
  const [copied, setCopied] = useState(false);

  const showToast = useCallback((message: string) => {
    if (Platform.OS === 'android') {
      ToastAndroid.show(message, ToastAndroid.SHORT);
    }
    // iOS: rely on haptic + visual feedback in UI
  }, []);

  const copy = useCallback(async (text: string, label: string = 'Copied') => {
    try {
      // Use expo-clipboard if available, fallback to RN Clipboard
      if (ClipboardExpo.setStringAsync) {
        await ClipboardExpo.setStringAsync(text);
      } else {
        Clipboard.setString(text);
      }
      
      setCopied(true);
      showToast(`${label} to clipboard`);
      
      // Reset copied state after 2 seconds
      setTimeout(() => setCopied(false), 2000);
    } catch (error) {
      console.error('Clipboard error:', error);
      showToast('Failed to copy');
    }
  }, [showToast]);

  return { copied, copy };
}