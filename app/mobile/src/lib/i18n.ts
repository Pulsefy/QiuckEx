import i18n from 'i18next';
import { initReactI18next } from 'react-i18next';
import translations from './i18n/translations.json';

// `translations` is the single source of truth for mobile copy. The key-parity
// check (scripts/check-i18n-parity.mjs, run in CI) reads this file directly so
// every locale stays in lockstep with the `en` base locale.
const resources = Object.fromEntries(
  Object.entries(translations).map(([lng, translation]) => [lng, { translation }]),
);

// React Native defines `window` but does not provide `localStorage` (web does),
// so read the persisted locale defensively — otherwise module evaluation throws
// on native and the bootstrap never runs.
const storage: Storage | undefined =
  typeof window !== 'undefined' ? window.localStorage : undefined;

const initialLanguage = storage?.getItem('i18nextLng') || 'en';

i18n
  .use(initReactI18next)
  .init({
    lng: initialLanguage,
    fallbackLng: 'en',
    interpolation: {
      escapeValue: false,
    },
    resources,
  });

if (storage) {
  i18n.on('languageChanged', (lng) => {
    storage.setItem('i18nextLng', lng);
  });
}

export default i18n;
