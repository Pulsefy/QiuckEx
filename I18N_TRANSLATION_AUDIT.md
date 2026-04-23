# i18n Translation Coverage Audit

Date: April 23, 2026
Status: Partially localized (i18next setup exists, but incomplete coverage)

---

## FRONTEND (Next.js) - app/frontend/

### Pages with Translation Needs

#### 1. **[app/page.tsx](app/frontend/src/app/page.tsx)**
- **Status**: ❌ NOT TRANSLATED
- **Hardcoded strings**:
  - "Privacy-focused <br /> payments on Stellar."
  - "Create unique, shareable usernames and generate instant payment requests for USDC or XLM. Powered by Soroban smart contracts for shielded transactions."
  - "Generate Link"
  - "Go to Dashboard"
  - "Shareable Usernames", "Claim your unique name like quickex.to/alex and receive payments easily."
  - Feature cards descriptions (more feature cards follow)
- **User-facing text**: Hero section, CTAs, feature descriptions

#### 2. **[app/dashboard/page.tsx](app/frontend/src/app/dashboard/page.tsx)**
- **Status**: ❌ NOT TRANSLATED
- **Hardcoded strings**:
  - "Loading dashboard..."
  - "No transactions yet. Create your first payment link!"
  - Sidebar links: "Dashboard", "Link Generator", "Marketplace"
  - Alert messages: "Storage TTL extended for 6 months!", "Storage deposit reclaimed and record cleaned up!"
- **User-facing text**: Sidebar navigation, error states, success messages

#### 3. **[app/generator/page.tsx](app/frontend/src/app/generator/page.tsx)**
- **Status**: ⚠️ PARTIALLY TRANSLATED (uses i18n for some strings, but inconsistent)
- **Needs coverage for**:
  - Button labels not yet in translation keys
  - Validation feedback messages that may be hardcoded
  - Form field helpers/descriptions
- **User-facing text**: Payment form, validation errors, path preview info

#### 4. **[app/settings/page.tsx](app/frontend/src/app/settings/page.tsx)**
- **Status**: ⚠️ PARTIALLY TRANSLATED (uses `t('settingsTitle')` and `t('profileCustomization')`)
- **Hardcoded strings**:
  - "← Back" link text
  - Tab labels (may be in nested content)
  - Form field labels and placeholders
  - Save button text ("Save Changes" - check if using key)
- **User-facing text**: Settings form, navigation, section headers

#### 5. **[app/marketplace/page.tsx](app/frontend/src/app/marketplace/page.tsx)**
- **Status**: ❌ NOT TRANSLATED
- **Hardcoded strings**:
  - Category labels: "All", "Trending", "Short", "OG", "Crypto", "Brand"
  - Category icons with labels (e.g., "🔥 Trending", "💎 OG")
  - Sort options: "Ending Soon", "Highest Bid", "Lowest Bid", "Most Bids"
  - Stats bar labels: "Total Volume", "Active Bids", "Watchers"
  - Bid modal content
- **User-facing text**: Marketplace filters, sorting, auction/bid information

#### 6. **[app/discovery/page.tsx](app/frontend/src/app/discovery/page.tsx)**
- **Status**: ❌ NOT TRANSLATED
- **Hardcoded strings**:
  - "Discover <span className='text-transparent bg-clip-text bg-gradient-to-r from-indigo-400 to-cyan-400'>QuickEx</span>"
  - "Find public profiles, connect with trending creators, and effortlessly send payments to active members of the community."
  - "Trending Profiles", "Recently Active"
  - "followers" label
  - "View Profile" link
  - Skeleton loading states (if any text)
- **User-facing text**: Discovery hero, section headers, profile cards

#### 7. **[app/[username]/page.tsx](app/frontend/src/app/[username]/page.tsx)**
- **Status**: ❌ NEEDS CHECK
- **Expected content**: Public profile page, likely has user bio, payment info, social links
- **Likely hardcoded**: Profile headers, "Send Payment" CTA, social link labels

### Components with Translation Needs

#### **[components/Header.tsx](app/frontend/src/components/Header.tsx)**
- **Status**: ✅ MOSTLY USING i18n
- **Uses**: `t('dashboard')`, `t('linkGenerator')`, `t('profileSettings')`
- **Still hardcoded**: "QuickEx" logo text (may intentionally stay English)

#### **[components/LocaleSwitcher.tsx](app/frontend/src/components/LocaleSwitcher.tsx)**
- **Status**: ❌ PARTIALLY TRANSLATED
- **Hardcoded strings**:
  - `<option value="en">English</option>`
  - Language option labels
- **Should translate**: Language names (but may want to preserve native names)

#### **[components/NetworkBadge.tsx](app/frontend/src/components/NetworkBadge.tsx)**
- **Status**: ❌ NOT TRANSLATED
- **Hardcoded strings**:
  - Network labels: "TESTNET", "FUTURENET", "MAINNET"
  - "(default)" text
- **User-facing text**: Network indicator badge

#### **[components/SearchBar.tsx](app/frontend/src/components/SearchBar.tsx)**
- **Status**: ❌ NOT TRANSLATED
- **Hardcoded strings**:
  - `placeholder="Search global profiles..."`
  - "Clear" button title
- **User-facing text**: Search input, helper text

#### **[components/UsernameCard.tsx](app/frontend/src/components/UsernameCard.tsx)**
- **Status**: ❌ NOT TRANSLATED
- **Hardcoded strings**:
  - Category labels with emojis: "🔥 Trending", "⚡ Short", "💎 OG", "₿ Crypto", "✦ Brand"
  - "✓ Verified" badge label
  - "Current Bid", "Ends In" stat labels
  - "Buy Now" pricing info
  - "Place Bid" button
- **User-facing text**: Marketplace card displays, bid information

#### **[components/BidModal.tsx](app/frontend/src/components/BidModal.tsx)**
- **Status**: ❌ NOT TRANSLATED
- **Hardcoded strings**:
  - "Place a Bid"
  - "Bid Placed!" success heading
  - Success message: "You're leading with {{amount}} USDC on @{{username}}."
  - Transaction details labels
  - "Done" button, "Place Bid" button
  - Error message displays
  - Form validation labels
- **User-facing text**: Auction form, success/error states, transaction confirmation

#### **[components/AnalyticsDashboard.tsx](app/frontend/src/components/AnalyticsDashboard.tsx)**
- **Status**: ❌ NOT TRANSLATED
- **Hardcoded strings**:
  - Date range labels: "24h", "7d", "30d", "All Time"
  - Chart tooltips/labels (likely)
  - Section headers for analytics
  - "Fetching data..." / loading states
- **User-facing text**: Analytics time range selector, chart labels

#### **[components/CreateAPIKeyModal.tsx](app/frontend/src/components/CreateAPIKeyModal.tsx)**
- **Status**: ❌ NOT TRANSLATED
- **Hardcoded strings**:
  - "Create New API Key"
  - "Key Name" label
  - Placeholder: "e.g. Production App"
  - "Scopes" label
  - Scope descriptions:
    - "Fetch and query payment links"
    - "Create and update payment links"
    - "Read transaction history"
    - "Look up registered usernames"
  - Form buttons ("Create", "Cancel", etc.)
  - Scope labels: "links:read", "links:write", "transactions:read", "usernames:read"
- **User-facing text**: API key creation form, scope explanations

#### **[components/QRPreview.tsx](app/frontend/src/components/QRPreview.tsx)**
- **Status**: ❌ NOT TRANSLATED
- **Hardcoded strings**:
  - "Ready to Scan" (uppercase label)
  - "Point your wallet camera here"
  - Empty state messages
- **User-facing text**: QR code preview instructions

---

## MOBILE (React Native/Expo) - app/mobile/

### Screens with Translation Needs

#### 1. **[app/index.tsx](app/mobile/app/index.tsx)** - Home Screen
- **Status**: ❌ PARTIALLY TRANSLATED
- **Hardcoded strings**:
  - "QuickEx" title
  - Subtitle text
  - Empty state message
  - Section headers
  - Pay Again, Pay New, Quick Receive shortcut labels
- **User-facing text**: Home screen layout, quick actions

#### 2. **[app/onboarding.tsx](app/mobile/app/onboarding.tsx)** - Onboarding Screen
- **Status**: ❌ NOT TRANSLATED
- **Event tracking**: Hardcoded event names, but should consider translating any user-facing UI
- **Delegates to**: OnboardingFlow component
- **User-facing text**: Should check OnboardingFlow component

#### 3. **[app/settings.tsx](app/mobile/app/settings.tsx)** - Settings Screen
- **Status**: ❌ MOSTLY NOT TRANSLATED
- **Hardcoded strings**:
  - "Settings" title
  - "Sound Effects" label
  - "🔔 Sound Effects" label
  - "Onboarding" section header
  - Theme and locale switcher labels
- **User-facing text**: Settings form, section headers, control labels

#### 4. **[app/link-generator.tsx](app/mobile/app/link-generator.tsx)** - Link Generator Screen
- **Status**: ⚠️ PARTIALLY USING i18n
- **Uses**: `const { t } = useTranslation();`
- **Needs translation keys for**:
  - Form labels: "Amount", "Recipient", "Asset"
  - Button labels
  - Error messages
  - Empty states
  - Asset loading feedback
- **User-facing text**: Payment link form, validation feedback

#### 5. **[app/transactions.tsx](app/mobile/app/transactions.tsx)** - Transactions Screen
- **Status**: ❌ NOT TRANSLATED
- **Hardcoded strings**:
  - Filter labels: 'All', 'Success', 'Pending'
  - Date range filter labels
  - Export buttons ("CSV Export", etc.)
  - Empty state: "No transactions"
  - Loading states
  - Status labels
- **User-facing text**: Transaction list filters, export options, status indicators

#### 6. **[app/quick-receive.tsx](app/mobile/app/quick-receive.tsx)** - Quick Receive Screen
- **Status**: ❌ NOT TRANSLATED
- **Hardcoded strings**:
  - "Quick Receive" title
  - "No username found." warning
  - "Claim one to start receiving payments." guidance
  - "@{{username}}" display
  - "Copy Link" button
  - "Share" button
  - Alert messages: "Copied" title, "Link copied to clipboard" message
- **User-facing text**: Receive link display, copy/share actions, alerts

#### 7. **[app/add-contact.tsx](app/mobile/app/add-contact.tsx)** - Add Contact Screen
- **Status**: ❌ NOT TRANSLATED
- **Hardcoded strings**:
  - "Add Contact" title
  - Placeholder: "Nickname (optional)"
  - Placeholder: "Address (required)"
  - Button text: "Save Contact" / "Saving..."
  - Alert: "Address is required"
  - Alert: "Failed to save contact"
- **User-facing text**: Contact form, validation messages, action buttons

#### 8. **[app/contacts.tsx](app/mobile/app/contacts.tsx)** - Contacts Screen
- **Status**: ❌ NOT TRANSLATED
- **Hardcoded strings**:
  - "Contacts" title
  - "Add Contact" button
  - "Loading..." state
  - Button labels: "Pay", "Edit", "Delete"
  - Alert: "Delete Contact" title
  - Alert: "Are you sure you want to delete {{contact}}?" message
  - Alert button labels: "Cancel", "Delete"
  - "(No Nickname)" placeholder text
- **User-facing text**: Contacts list, action buttons, confirmation dialogs

#### 9. **[app/edit-contact.tsx](app/mobile/app/edit-contact.tsx)** - Edit Contact Screen
- **Status**: ❌ NEEDS CHECK
- **Expected hardcoded strings**: Form labels, buttons ("Update", "Delete Contact", etc.)

#### 10. **[app/payment-confirmation.tsx](app/mobile/app/payment-confirmation.tsx)** - Payment Confirmation Screen
- **Status**: ❌ NOT TRANSLATED
- **Hardcoded strings**:
  - "Authentication Required" alert
  - "You must authenticate with biometrics or PIN before sending payment." message
  - "Pay with Wallet" button
  - Asset selector labels
  - Swap/path payment explanation text
  - Success/error messages
  - Amount display and formatting
- **User-facing text**: Payment authorization, confirmation details, error handling

#### 11. **[app/scan-to-pay.tsx](app/mobile/app/scan-to-pay.tsx)** - Scan to Pay Screen
- **Status**: ❌ NEEDS CHECK
- **Expected content**: QR scanner UI, likely has instructions and buttons

#### 12. **[app/security.tsx](app/mobile/app/security.tsx)** - Security Screen
- **Status**: ❌ NOT TRANSLATED
- **Hardcoded strings**:
  - "Security" title
  - "Protect sensitive flows with biometrics and a fallback PIN." subtitle
  - "Biometric Lock" label (likely)
  - "PIN Configuration" section
  - Alert messages:
    - "PIN mismatch" title
    - "PIN and confirmation must match." message
    - "Invalid PIN" title
    - "Please check the PIN format." message
    - "PIN saved" title
    - "Fallback PIN is now configured securely." message
    - "Security setup required" title
    - Alert confirmations for toggle states
- **User-facing text**: Security settings form, PIN setup, biometric configuration

#### 13. **[app/wallet-connect.tsx](app/mobile/app/wallet-connect.tsx)** - Wallet Connect Screen
- **Status**: ❌ NEEDS CHECK
- **Expected content**: Wallet connection instructions and UI

### Components with Translation Needs

#### **[components/LocaleSwitcher.tsx](app/mobile/components/LocaleSwitcher.tsx)**
- **Status**: ✅ USES i18n
- **Uses**: `const { i18n } = useTranslation();`
- **Already integrated** with language switching

#### **[components/ThemeSelector.tsx](app/mobile/components/ThemeSelector.tsx)**
- **Status**: ❌ NOT TRANSLATED
- **Hardcoded strings**:
  - "Appearance" heading
  - "Choose how QuickEx looks on your device" subheading
  - Mode options:
    - "☀️ Light" label, "Classic bright interface" description
    - "🌙 Dark" label, "Easy on the eyes" description
    - "⚙️ System" label, "Follows device setting" description
  - Brand theme labels and descriptions
- **User-facing text**: Theme selection UI, mode descriptions

#### **[components/notifications/NotificationCenter.tsx](app/mobile/components/notifications/NotificationCenter.tsx)**
- **Status**: ❌ NEEDS CHECK
- **Expected content**: Notification UI with messages and actions

#### **[components/onboarding/OnboardingFlow.tsx](app/mobile/components/onboarding/OnboardingFlow.tsx)**
- **Status**: ❌ NEEDS CHECK
- **Expected content**: Multi-step onboarding flow with step headers, instructions, buttons

#### **[components/onboarding/OnboardingResetButton.tsx](app/mobile/components/onboarding/OnboardingResetButton.tsx)**
- **Status**: ❌ NEEDS CHECK
- **Expected content**: Reset onboarding button and confirmation text

#### **[components/security/...](app/mobile/components/security/)**
- **Status**: ❌ NEEDS CHECK
- **Expected content**: Security-related sub-components

#### **[components/resilience/error-state.tsx](app/mobile/components/resilience/error-state.tsx)**
- **Status**: ❌ NOT TRANSLATED
- **Likely contains**: "Try Again" button, error messages, retry logic

#### **[components/resilience/empty-state.tsx](app/mobile/components/resilience/empty-state.tsx)**
- **Status**: ❌ NOT TRANSLATED
- **Likely contains**: "No data found", "Get started" CTA, empty state messages

#### **[components/transaction-item.tsx](app/mobile/components/transaction-item.tsx)**
- **Status**: ❌ NEEDS CHECK
- **Expected content**: Transaction details display with labels and status

#### **[components/wallet/...](app/mobile/components/wallet/)**
- **Status**: ❌ NEEDS CHECK
- **Expected content**: Wallet-related components

#### **[components/swap-asset-selector.tsx](app/mobile/components/swap-asset-selector.tsx)**
- **Status**: ❌ NOT TRANSLATED
- **Likely contains**: Asset selector UI, labels, instructions

#### **[components/swap-rate-details.tsx](app/mobile/components/swap-rate-details.tsx)**
- **Status**: ❌ NOT TRANSLATED
- **Likely contains**: Swap rate information, labels, rate breakdown

#### **[components/themed-text.tsx](app/mobile/components/themed-text.tsx)**
- **Status**: ⚠️ COMPONENT-LEVEL (shouldn't have user-facing text)
- **Note**: This is a styled text component, not content

#### **[components/themed-view.tsx](app/mobile/components/themed-view.tsx)**
- **Status**: ⚠️ COMPONENT-LEVEL (shouldn't have user-facing text)
- **Note**: This is a styled view component, not content

#### **[components/QRPreviewModal.tsx](app/mobile/components/QRPreviewModal.tsx)**
- **Status**: ❌ NOT TRANSLATED
- **Likely contains**: Modal close button, QR display instructions

#### **[components/haptic-tab.tsx](app/mobile/components/haptic-tab.tsx)**
- **Status**: ⚠️ COMPONENT-LEVEL
- **Note**: Navigation component, may need tab labels

#### **[components/parallax-scroll-view.tsx](app/mobile/components/parallax-scroll-view.tsx)**
- **Status**: ⚠️ COMPONENT-LEVEL
- **Note**: Layout component, shouldn't have user-facing text

#### **[components/external-link.tsx](app/mobile/components/external-link.tsx)**
- **Status**: ⚠️ COMPONENT-LEVEL
- **Note**: Link wrapper component

#### **[components/hello-wave.tsx](app/mobile/components/hello-wave.tsx)**
- **Status**: ❌ NEEDS CHECK
- **Likely contains**: Welcome message or greeting

---

## Summary Statistics

### Frontend (Next.js)
- **Total Pages**: 7 (including dynamic route)
- **Not Translated**: 6 ❌
- **Partially Translated**: 1 ⚠️
- **Well Translated**: 0 ✅

- **Total Components**: 9
- **Not Translated**: 8 ❌
- **Partially Translated**: 1 ⚠️
- **Well Translated**: 0 ✅

### Mobile (React Native)
- **Total Screens**: 13
- **Not Translated**: 11 ❌
- **Partially Translated**: 2 ⚠️
- **Well Translated**: 0 ✅

- **Total Components**: 16+ (excluding styled components)
- **Not Translated**: 14+ ❌
- **Partially Translated**: 1 ⚠️
- **Well Translated**: 1 ✅

---

## Current i18n Infrastructure

### Configured
- **Frontend**: [src/lib/i18n.ts](app/frontend/src/lib/i18n.ts) with English translation keys
- **Mobile**: Uses `react-i18next` via LocaleSwitcher
- **Packages**: i18next, react-i18next already installed

### Translation Keys Already Available (Frontend)
```
Navigation:
- dashboard, linkGenerator, settings, profileSettings, services, settingsTitle
- profileCustomization, profileCustomizationDescription, generalTab, developerTab

Settings:
- themeSettings, primaryColor, avatarUrl, bioLabel, socialLinks
- twitterHandleLabel, discordUsernameLabel, githubHandleLabel
- languageLabel, changeLanguage, saveChanges, preview, show, hide, livePreview

Generator Page:
- createPayment, requestInstantly, advancedModeDescription, amountLabel, amountPlaceholder
- loadingAssets, destinationLabel, memoLabel, memoPlaceholder, advancedSettings
- recipientAsset, recipientAssetDescription, allowedSourceAssets, pathPreview
- sorobanPreflight, simulationOk, totalFee, latency

Errors:
- amountRequired, enterValidNumber, destinationRequired, selectRecipientAsset
- couldNotLoadAssets, invalidPublicKey, preflightUnavailable, preflightFailed
- networkError, requestFailed

Footer:
- copyright, github, terms, privacy
```

---

## Recommended Priority for Translation Coverage

### High Priority (Critical UX)
1. Home page hero and CTAs
2. Main navigation and sidebar
3. Error/validation messages
4. Form labels (all apps)
5. Action buttons (Pay, Send, Save, etc.)

### Medium Priority (Important UX)
1. Dashboard statistics and headers
2. Settings panel labels
3. Marketplace filters and sort options
4. Transaction/contact management screens
5. Modal dialogs and alerts

### Low Priority (Supporting UX)
1. Placeholder text
2. Status badges and labels
3. Component-level styled elements
4. Analytics chart labels
5. Network indicators

---

## Next Steps for Implementation
1. Extract all hardcoded strings into i18n keys
2. Decide on supported languages (beyond English)
3. Create language-specific resource files
4. Add i18n integration to all remaining components/screens
5. Test locale switching across all pages/screens
6. Consider RTL language support if needed
7. Set up CI/CD checks for untranslated strings
