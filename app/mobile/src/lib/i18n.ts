import i18n from 'i18next';
import { initReactI18next } from 'react-i18next';
import translations from './i18n/translations.json';

// `translations` is the single source of truth for mobile copy. The key-parity
// check (scripts/check-i18n-parity.mjs, run in CI) reads this file directly so
// every locale stays in lockstep with the `en` base locale.
const resources = Object.fromEntries(
  Object.entries(translations).map(([lng, translation]) => [lng, { translation }]),
);

const initialLanguage = typeof window !== 'undefined'
  ? window.localStorage.getItem('i18nextLng') || 'en'
  : 'en';

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

if (typeof window !== 'undefined') {
  i18n.on('languageChanged', (lng) => {
    window.localStorage.setItem('i18nextLng', lng);
  });
}

export default i18n;
