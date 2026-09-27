import { useState, useCallback } from 'react';
import { copyToClipboard } from '../utils/clipboard';

export function useClipboard() {
  const [copied, setCopied] = useState(false);

  const copy = useCallback(async (text: string, label?: string) => {
    const success = await copyToClipboard(text);
    if (success) {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
    return success;
  }, []);

  return { copied, copy };
}
