import i18n from 'i18next';
import { initReactI18next } from 'react-i18next';

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
        translation: {
          // Navigation
          dashboard: 'Dashboard',
          linkGenerator: 'Link Generator',
          settings: 'Settings',
          profileSettings: 'Profile Settings',
          services: 'Services',

          // Generator page
          createPayment: 'Create a payment',
          requestInstantly: 'request instantly.',
          advancedModeDescription: 'Advanced mode supports path payments: choose what you receive and let payers settle in multiple assets.',
          amountLabel: 'Amount (recipient receives)',
          amountPlaceholder: '0.00',
          loadingAssets: 'Loading assets…',
          destinationLabel: 'Destination',
          destinationPlaceholder: 'Receiver public key',
          memoLabel: 'Memo (optional)',
          memoPlaceholder: "What's this payment for?",
          advancedSettings: 'Advanced settings',
          hide: 'Hide',
          show: 'Show',
          recipientAsset: 'Recipient asset',
          recipientAssetDescription: 'Same as the amount currency above — what lands in the receiver\'s account after the path executes.',
          allowedSourceAssets: 'Allowed source assets (payers)',
          allowedSourceAssetsDescription: 'Payers may use any of the selected assets; Horizon suggests paths and send amounts.',
          pathPreview: 'Path preview',
          fetchingEstimates: 'Fetching estimates…',
          noPathsFound: 'No paths found for this combination on {{horizonUrl}}. Try other source assets or a smaller amount.',
          payReceive: 'Pay {{sourceAmount}} ({{sourceAsset}}) → receive {{destinationAmount}} ({{destinationAsset}})',
          hops: 'Hops: {{hopCount}}',
          sorobanPreflight: 'Soroban preflight (composer)',
          sorobanPreflightDescription: 'Runs the same simulation as POST /transactions/compose with health_check on QUICKEX_CONTRACT_ID.',
          sourceAccountPlaceholder: 'Source account G… (funded, for sequence)',
          simulating: 'Simulating…',
          runPreflight: 'Run preflight simulation',
          simulationOk: 'Simulation OK — fees estimated.',
          totalFee: 'Total fee (incl. resource): {{totalFee}} XLM',
          latency: 'Latency {{latency}} ms',
          simulationFailed: 'Simulation failed',

          // Errors
          amountRequired: 'Amount is required.',
          enterValidNumber: 'Enter a valid number.',
          destinationRequired: 'Destination address is required.',
          selectRecipientAsset: 'Select a recipient asset.',
          couldNotLoadAssets: 'Could not load verified assets.',
          invalidPublicKey: 'Enter a valid 56-character Stellar public key (G…).',
          preflightUnavailable: 'Soroban preflight is not configured on this server.',
          preflightFailed: 'Preflight request failed.',
          networkError: 'Network error calling preflight.',
          requestFailed: 'Request failed',

          // Mobile specific
          generateLink: 'Generate Link',
          linkReady: 'Link Ready!',
          shareLink: 'Share Link',
          copyLink: 'Copy Link',
          previewQR: 'Preview QR Code',
          notificationsTitle: 'Notifications',
          close: 'Close',
          noNotifications: 'No notifications',

          // Home screen
          appTitle: 'QuickEx',
          appSubtitle: 'Your global payment companion',
          payAgain: 'Pay Again',
          payNew: 'Pay New',
          quickReceive: 'Quick Receive',
          recentContacts: 'Recent Contacts',
          noRecentContacts: 'No recent contacts',
          getStarted: 'Get Started',
          instantPayments: 'Instant Payments',
          instantPaymentsDesc: 'Receive USDC, XLM, or any Stellar asset directly to your self-custody wallet.',
          scanToPay: 'Scan to Pay',
          connectWallet: 'Connect Wallet',
          contacts: 'Contacts',
        }
      },
      es: {
        translation: {
          // Navigation
          dashboard: 'Panel de Control',
          linkGenerator: 'Generador de Enlaces',
          settings: 'Configuración',
          profileSettings: 'Configuración de Perfil',
          services: 'Servicios',

          // Generator page
          createPayment: 'Crear un pago',
          requestInstantly: 'solicitud al instante.',
          advancedModeDescription: 'El modo avanzado soporta pagos de ruta: elige lo que recibes y deja que los pagadores se liquiden en múltiples activos.',
          amountLabel: 'Cantidad (recibe el destinatario)',
          amountPlaceholder: '0.00',
          loadingAssets: 'Cargando activos…',
          destinationLabel: 'Destino',
          destinationPlaceholder: 'Clave pública del receptor',
          memoLabel: 'Memo (opcional)',
          memoPlaceholder: '¿Para qué es este pago?',
          advancedSettings: 'Configuración avanzada',
          recipientAsset: 'Activo del destinatario',
          recipientAssetDescription: 'Igual a la moneda de la cantidad anterior — lo que llega a la cuenta del receptor después de que se ejecute la ruta.',
          allowedSourceAssets: 'Activos fuente permitidos (pagadores)',
          allowedSourceAssetsDescription: 'Los pagadores pueden usar cualquiera de los activos seleccionados; Horizon sugiere rutas y envía cantidades.',
          pathPreview: 'Vista previa de ruta',
          fetchingEstimates: 'Obteniendo estimaciones…',
          noPathsFound: 'No se encontraron rutas para esta combinación en {{horizonUrl}}. Prueba otros activos fuente o una cantidad menor.',
          payReceive: 'Pagar {{sourceAmount}} ({{sourceAsset}}) → recibir {{destinationAmount}} ({{destinationAsset}})',
          hops: 'Saltos: {{hopCount}}',
          sorobanPreflight: 'Preflight de Soroban (compositor)',
          sorobanPreflightDescription: 'Ejecuta la misma simulación que POST /transactions/compose con health_check en QUICKEX_CONTRACT_ID.',
          sourceAccountPlaceholder: 'Cuenta fuente G… (financiada, para secuencia)',
          simulating: 'Simulando…',
          runPreflight: 'Ejecutar simulación de preflight',
          simulationOk: 'Simulación OK — tarifas estimadas.',
          totalFee: 'Tarifa total (incl. recurso): {{totalFee}} XLM',
          latency: 'Latencia {{latency}} ms',
          simulationFailed: 'Simulación fallida',

          // Errors
          amountRequired: 'La cantidad es requerida.',
          enterValidNumber: 'Ingresa un número válido.',
          destinationRequired: 'La dirección de destino es requerida.',
          selectRecipientAsset: 'Selecciona un activo del destinatario.',
          couldNotLoadAssets: 'No se pudieron cargar los activos verificados.',
          invalidPublicKey: 'Ingresa una clave pública Stellar válida de 56 caracteres (G…).',
          preflightUnavailable: 'El preflight de Soroban no está configurado en este servidor.',
          preflightFailed: 'La solicitud de preflight falló.',
          networkError: 'Error de red llamando a preflight.',
          requestFailed: 'Solicitud fallida',

          // Mobile specific
          generateLink: 'Generar Enlace',
          linkReady: '¡Enlace Listo!',
          shareLink: 'Compartir Enlace',
          copyLink: 'Copiar Enlace',
          previewQR: 'Vista Previa QR',
          notificationsTitle: 'Notificaciones',
          close: 'Cerrar',
          noNotifications: 'Sin notificaciones',

          // Home screen
          appTitle: 'QuickEx',
          appSubtitle: 'Tu compañero de pagos globales',
          payAgain: 'Pagar de Nuevo',
          payNew: 'Pagar Nuevo',
          quickReceive: 'Recepción Rápida',
          recentContacts: 'Contactos Recientes',
          noRecentContacts: 'Sin contactos recientes',
          getStarted: 'Comenzar',
        }
      },
      fr: {
        translation: {
          // Navigation
          dashboard: 'Tableau de Bord',
          linkGenerator: 'Générateur de Liens',
          settings: 'Paramètres',
          profileSettings: 'Paramètres de Profil',
          services: 'Services',

          // Generator page
          createPayment: 'Créer un paiement',
          requestInstantly: 'demande instantanément.',
          advancedModeDescription: 'Le mode avancé prend en charge les paiements de chemin : choisissez ce que vous recevez et laissez les payeurs se liquider dans plusieurs actifs.',
          amountLabel: 'Montant (reçu par le destinataire)',
          amountPlaceholder: '0.00',
          loadingAssets: 'Chargement des actifs…',
          destinationLabel: 'Destination',
          destinationPlaceholder: 'Clé publique du destinataire',
          memoLabel: 'Mémo (optionnel)',
          memoPlaceholder: 'À quoi sert ce paiement ?',
          advancedSettings: 'Paramètres avancés',
          recipientAsset: 'Actif du destinataire',
          recipientAssetDescription: 'Identique à la devise du montant ci-dessus — ce qui arrive sur le compte du destinataire après l\'exécution du chemin.',
          allowedSourceAssets: 'Actifs source autorisés (payeurs)',
          allowedSourceAssetsDescription: 'Les payeurs peuvent utiliser n\'importe quel actif sélectionné ; Horizon suggère des chemins et envoie des montants.',
          pathPreview: 'Aperçu du chemin',
          fetchingEstimates: 'Récupération des estimations…',
          noPathsFound: 'Aucun chemin trouvé pour cette combinaison sur {{horizonUrl}}. Essayez d\'autres actifs source ou un montant plus petit.',
          payReceive: 'Payer {{sourceAmount}} ({{sourceAsset}}) → recevoir {{destinationAmount}} ({{destinationAsset}})',
          hops: 'Sauts : {{hopCount}}',
          sorobanPreflight: 'Pré-vol Soroban (compositeur)',
          sorobanPreflightDescription: 'Exécute la même simulation que POST /transactions/compose avec health_check sur QUICKEX_CONTRACT_ID.',
          sourceAccountPlaceholder: 'Compte source G… (financé, pour séquence)',
          simulating: 'Simulation…',
          runPreflight: 'Exécuter la simulation de pré-vol',
          simulationOk: 'Simulation OK — frais estimés.',
          totalFee: 'Frais total (incl. ressource) : {{totalFee}} XLM',
          latency: 'Latence {{latency}} ms',
          simulationFailed: 'Échec de la simulation',

          // Errors
          amountRequired: 'Le montant est requis.',
          enterValidNumber: 'Entrez un nombre valide.',
          destinationRequired: 'L\'adresse de destination est requise.',
          selectRecipientAsset: 'Sélectionnez un actif destinataire.',
          couldNotLoadAssets: 'Impossible de charger les actifs vérifiés.',
          invalidPublicKey: 'Entrez une clé publique Stellar valide de 56 caractères (G…).',
          preflightUnavailable: 'Le pré-vol Soroban n\'est pas configuré sur ce serveur.',
          preflightFailed: 'La demande de pré-vol a échoué.',
          networkError: 'Erreur réseau lors de l\'appel du pré-vol.',
          requestFailed: 'Échec de la demande',

          // Home screen
          appTitle: 'QuickEx',
          appSubtitle: 'Votre compagnon de paiement mondial',
          payAgain: 'Payer Encore',
          payNew: 'Nouveau Paiement',
          quickReceive: 'Réception Rapide',
          recentContacts: 'Contacts Récents',
          noRecentContacts: 'Aucun contact récent',
          getStarted: 'Commencer',

          // Mobile specific
          generateLink: 'Générer un Lien',
          linkReady: 'Lien Prêt !',
          shareLink: 'Partager le Lien',
          copyLink: 'Copier le Lien',
          previewQR: 'Aperçu QR',
          notificationsTitle: 'Notifications',
          close: 'Fermer',
          noNotifications: 'Aucune notification',
        }
      }
    }
  });

if (typeof window !== 'undefined') {
  i18n.on('languageChanged', (lng) => {
    window.localStorage.setItem('i18nextLng', lng);
  });
}

export default i18n;