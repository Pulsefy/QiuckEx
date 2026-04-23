'use client';

import '@/lib/i18n';
import { useTranslation } from 'react-i18next';

export function LocaleSwitcher() {
  const { i18n } = useTranslation();

  const changeLanguage = (lng: string) => {
    i18n.changeLanguage(lng);
  };

  return (
    <select
      value={i18n.language}
      onChange={(e) => changeLanguage(e.target.value)}
      className="bg-neutral-900 border border-white/10 rounded-lg px-3 py-1 text-sm"
    >
      <option value="en">English</option>
      <option value="es">Español</option>
      <option value="fr">Français</option>
    </select>
  );
}