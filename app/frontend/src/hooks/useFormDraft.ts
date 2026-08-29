"use client";

import { useCallback, useEffect, useState } from "react";
import {
  clearFormDraft,
  loadFormDraft,
  saveFormDraft,
} from "@/lib/auth-session";

/**
 * Form state that persists to session storage so in-progress input survives a
 * re-authentication round trip (FE-70). Restores any saved draft on mount.
 *
 * Returns a `[value, setValue, clear]` tuple; `setValue` both updates state and
 * persists the draft, and `clear` removes the persisted draft.
 */
export function useFormDraft<T>(
  key: string,
  initial: T,
): readonly [T, (next: T) => void, () => void] {
  const [value, setValue] = useState<T>(initial);

  useEffect(() => {
    const saved = loadFormDraft<T>(key);
    if (saved !== null) {
      setValue(saved);
    }
  }, [key]);

  const update = useCallback(
    (next: T) => {
      setValue(next);
      saveFormDraft(key, next);
    },
    [key],
  );

  const clear = useCallback(() => {
    clearFormDraft(key);
    setValue(initial);
  }, [key, initial]);

  return [value, update, clear] as const;
}
