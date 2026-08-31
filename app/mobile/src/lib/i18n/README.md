# Mobile i18n

Mobile copy lives in [`translations.json`](./translations.json) and is loaded by
[`i18n.ts`](../i18n.ts) into `i18next`. `en` is the **base locale**; every other
locale (`es`, `fr`, …) must expose the exact same set of keys.

## Why a JSON file?

The dictionary is plain JSON (not inline TypeScript) so the CI parity check can
read it without parsing source. Keep all mobile strings here — do not add
hard-coded translatable strings elsewhere.

## Key parity

A CI job (`scripts/check-i18n-parity.mjs`, wired into `.github/workflows/mobile-ci.yml`)
fails the build when a non-base locale is missing a key that exists in `en`. It
reports the missing keys per locale by name, e.g.:

```
❌ es: missing 2 key(s) present in en:
     - hide
     - show
```

Run it locally with:

```bash
pnpm --filter mobile check:i18n
# or
node app/mobile/scripts/check-i18n-parity.mjs
```

The same invariant is covered by a unit test
(`app/mobile/__tests__/i18n-key-parity.test.ts`).

### Rules

- When you add a key to `en`, add it (translated) to **every** other locale.
- When you remove a key from `en`, remove it from every other locale.
- Dead keys (present in a locale but not in `en`) are printed as warnings.

## Staying comparable with the frontend

The web app keeps its own dictionary in
`app/frontend/src/lib/i18n.ts`. The keys below are **conceptually shared** with the
mobile dictionary — they describe the same UI concept and should be kept
comparable (and translated consistently) across both surfaces. When you change the
meaning of one of these keys, check the counterpart in the frontend.

### Shared keys (identical key name in both `app/mobile` and `app/frontend`)

`dashboard`, `linkGenerator`, `settings`, `profileSettings`, `services`,
`createPayment`, `requestInstantly`, `advancedModeDescription`, `amountLabel`,
`amountPlaceholder`, `loadingAssets`, `destinationLabel`, `destinationPlaceholder`,
`memoLabel`, `memoPlaceholder`, `advancedSettings`, `hide`, `show`,
`recipientAsset`, `recipientAssetDescription`, `allowedSourceAssets`,
`allowedSourceAssetsDescription`, `pathPreview`, `fetchingEstimates`, `noPathsFound`,
`payReceive`, `hops`, `sorobanPreflight`, `sorobanPreflightDescription`,
`sourceAccountPlaceholder`, `simulating`, `runPreflight`, `simulationOk`,
`totalFee`, `latency`, `simulationFailed`, `amountRequired`, `enterValidNumber`,
`destinationRequired`, `selectRecipientAsset`, `couldNotLoadAssets`,
`invalidPublicKey`, `preflightUnavailable`, `preflightFailed`, `networkError`,
`requestFailed`, `generateLink`, `instantPayments`, `instantPaymentsDesc`.

### Mobile-only keys (no frontend counterpart)

`linkReady`, `shareLink`, `copyLink`, `previewQR`, `notificationsTitle`, `close`,
`noNotifications`, `appTitle`, `appSubtitle`, `payAgain`, `payNew`, `quickReceive`,
`recentContacts`, `noRecentContacts`, `getStarted`, `scanToPay`, `connectWallet`,
`contacts`.
