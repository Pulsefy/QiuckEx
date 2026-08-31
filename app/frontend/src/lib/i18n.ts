import i18n from 'i18next';
import { initReactI18next } from 'react-i18next';
import translations from './i18n/translations.json';

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
    resources: {
      en: {
        translation: translations.en,
      },
      es: {
        translation: translations.es,
      },
      fr: {
        translation: translations.fr,
      },
    },
  });

if (typeof window !== 'undefined') {
  i18n.on('languageChanged', (lng) => {
    window.localStorage.setItem('i18nextLng', lng);
  });
}

export default i18n;
