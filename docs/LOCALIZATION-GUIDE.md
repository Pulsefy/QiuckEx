# Localization Contributor Guide

QuickEx ships user-facing copy on two clients — the Next.js web app (`app/frontend`) and the Expo mobile app (`app/mobile`). Each maintains its **own** `i18next` dictionary. There is no shared package, no translation-management platform, and no automated sync between them.

This guide covers adding a string, adding a locale, and the conventions that keep the two dictionaries comparable. It ends with the **known drift** between them, which is the starting point for anyone doing translation work today.

Companion documents:

- [`app/mobile/src/lib/i18n/README.md`](../app/mobile/src/lib/i18n/README.md) — mobile-local notes and the shared-key inventory.
- [CAPABILITY-MAP.md](./CAPABILITY-MAP.md) — which surfaces are Live vs Mocked, which tells you whether a screen is worth translating yet.

---

## 1. Where the strings live

| | Frontend | Mobile |
|---|---|---|
| Dictionary | [`app/frontend/src/lib/i18n/translations.json`](../app/frontend/src/lib/i18n/translations.json) | [`app/mobile/src/lib/i18n/translations.json`](../app/mobile/src/lib/i18n/translations.json) |
| `i18next` bootstrap | [`app/frontend/src/lib/i18n.ts`](../app/frontend/src/lib/i18n.ts) | [`app/mobile/src/lib/i18n.ts`](../app/mobile/src/lib/i18n.ts) |
| Locale picker | [`app/frontend/src/components/LocaleSwitcher.tsx`](../app/frontend/src/components/LocaleSwitcher.tsx) | [`app/mobile/components/LocaleSwitcher.tsx`](../app/mobile/components/LocaleSwitcher.tsx) |
| Parity check | [`app/frontend/scripts/check-i18n-parity.mjs`](../app/frontend/scripts/check-i18n-parity.mjs) | [`app/mobile/scripts/check-i18n-parity.mjs`](../app/mobile/scripts/check-i18n-parity.mjs) |
| Parity test | [`app/frontend/__tests__/i18n-parity.test.ts`](../app/frontend/__tests__/i18n-parity.test.ts) | [`app/mobile/__tests__/i18n-key-parity.test.ts`](../app/mobile/__tests__/i18n-key-parity.test.ts) |
| CI job | [`.github/workflows/frontend-ci.yml`](../.github/workflows/frontend-ci.yml) | [`.github/workflows/mobile-ci.yml`](../.github/workflows/mobile-ci.yml) |
| Number/date formatting | [`app/frontend/src/lib/formatting.ts`](../app/frontend/src/lib/formatting.ts) | **none — see §6** |

Both dictionaries are plain JSON with the shape `{ "<locale>": { "<key>": "<string>" } }`, both carry `en`, `es`, and `fr`, and `en` is the **base locale** on both.

JSON rather than inline TypeScript is deliberate: the CI parity checks read the file without parsing source.

> The `i18n.ts.backup` file that previously sat in the frontend tree **no longer exists**. If you find a reference to it, that reference is stale.

---

## 2. Adding a translatable string

### Frontend

1. **Add the key to all three locales** in [`src/lib/i18n/translations.json`](../app/frontend/src/lib/i18n/translations.json). All of `en`, `es`, and `fr` — the frontend parity check treats a missing key as a hard failure. If you do not have a real translation, ship the English text as a placeholder and note it in the PR; a missing key breaks the build, an untranslated one does not.

   ```json
   {
     "en": { "cancelPayment": "Cancel payment" },
     "es": { "cancelPayment": "Cancelar pago" },
     "fr": { "cancelPayment": "Annuler le paiement" }
   }
   ```

2. **Use it from a client component.** `useTranslation` requires the React context, so the component needs `'use client'`:

   ```tsx
   'use client';
   import { useTranslation } from 'react-i18next';

   export function CancelButton() {
     const { t } = useTranslation();
     return <button>{t('cancelPayment')}</button>;
   }
   ```

   The `i18next` instance is initialised by the side-effect import `import '@/lib/i18n'`. Server components cannot call `t()` — pass translated text down as props, or make the leaf a client component.

3. **Verify:** `pnpm --filter frontend check:i18n`

### Mobile

1. **Add the key to all three locales** in [`src/lib/i18n/translations.json`](../app/mobile/src/lib/i18n/translations.json). Same rule.

2. **Use it from a screen or component:**

   ```tsx
   import { useTranslation } from 'react-i18next';

   export function CancelButton() {
     const { t } = useTranslation();
     return <Text>{t('cancelPayment')}</Text>;
   }
   ```

   Mobile derives its `resources` object from the JSON automatically, so no bootstrap edit is needed when adding a key — or a locale.

3. **Verify:** `pnpm --filter mobile check:i18n`

> **Before you test on mobile, read [drift item D1](#d1-the-mobile-i18n-bootstrap-import-is-broken).** The mobile bootstrap import is currently broken, so `t()` returns raw key names at runtime regardless of what is in the dictionary. Fixing that one-character path is a prerequisite for any mobile translation work being visible.

### If the string appears on both clients

Add it to both dictionaries, **under the same key name**, with the same meaning. Nothing enforces this — the two parity checks run independently and neither is aware of the other. See §4.

---

## 3. Key naming conventions

The dictionaries use a **flat, single-level namespace**. There is no nesting and no `feature:key` prefixing today, on either client. Follow the existing shape rather than introducing a nested tree for one feature.

| Rule | Example |
|---|---|
| `camelCase`, no dots, no dashes, no underscores | `allowedSourceAssets` |
| Name the **concept**, not the location or the widget | `destinationRequired`, not `formError3` or `payPageInputError` |
| Suffix a longer explanatory string with `Description` | `recipientAsset` / `recipientAssetDescription` |
| Suffix placeholder text with `Placeholder` | `destinationLabel` / `destinationPlaceholder` |
| Validation and error messages read as complete sentences ending in a period | `"Destination is required."` |
| Labels, buttons, and headings do not end in a period | `"Run preflight"` |
| Never key on the English text | `cancelPayment`, not `cancel_payment_button_text` |

### Shared versus client-specific keys

> **The rule: a key is shared when the same UI concept exists on both clients. Shared keys use the same name on both, and their `en` values must match exactly.**

Three categories:

- **Shared** — the concept exists on both clients. Use one key name on both. Changing the meaning on one means changing it on the other in the same PR. There are currently **49** such keys, inventoried in the [mobile README](../app/mobile/src/lib/i18n/README.md).
- **Frontend-only** — web surfaces with no mobile counterpart (webhooks, API keys, analytics, marketplace, admin). **80** keys today. Do not mirror these into mobile "for symmetry" — an untranslated dead key is worse than an absent one, and the frontend parity check treats dead keys as failures.
- **Mobile-only** — native concepts with no web counterpart: `linkReady`, `shareLink`, `copyLink`, `previewQR`, `notificationsTitle`, `close`, `noNotifications`, `appTitle`, `appSubtitle`, `payAgain`, `payNew`, `quickReceive`, `recentContacts`, `noRecentContacts`, `getStarted`, `scanToPay`, `connectWallet`, `contacts`. **18** keys today.

When you add a key, decide which category it is in and act accordingly. When you *change* a shared key's English text, update both dictionaries — otherwise you add to the drift catalogued in §7.

---

## 4. Keeping the two clients aligned

There is **no tooling that compares the frontend and mobile dictionaries**. Both parity checks only compare locales *within* one client against that client's `en`. Cross-client alignment is a review responsibility.

The two checks are also not identical in strictness:

| | Missing key (in a locale, present in `en`) | Dead key (in a locale, absent from `en`) |
|---|---|---|
| Frontend | ❌ exit 1 | ❌ exit 1 |
| Mobile | ❌ exit 1 | ⚠️ warning, exit 0 |

Both honour `I18N_BASE_LOCALE` to override the base locale, and both accept an explicit dictionary path as `argv[2]`.

**Checklist when touching a shared key:**

- [ ] Same key name in both dictionaries.
- [ ] Identical `en` value in both.
- [ ] All three locales updated in both.
- [ ] Interpolation placeholders identical in name and count across every locale and both clients.
- [ ] Shared-key inventory in the [mobile README](../app/mobile/src/lib/i18n/README.md) updated if the key moved category.
- [ ] `pnpm --filter frontend check:i18n` and `pnpm --filter mobile check:i18n` both pass.

---

## 5. Adding a new locale

Adding a locale is **one step on mobile and three on the frontend**, because the frontend bootstrap hardcodes its resource map while mobile derives it.

### Frontend

1. **Translate every key.** Copy the `en` block in `src/lib/i18n/translations.json`, add it under the new locale code, translate all 129 values. The parity check fails on any missing key, so a partial locale cannot land.

2. **Register it in the bootstrap.** [`src/lib/i18n.ts`](../app/frontend/src/lib/i18n.ts) lists each locale explicitly:

   ```ts
   resources: {
     en: { translation: translations.en },
     es: { translation: translations.es },
     fr: { translation: translations.fr },
     de: { translation: translations.de },   // ← add
   },
   ```

   **Skipping this step is silent.** The parity check passes, CI is green, and the locale simply never loads. Consider replacing this block with the derived form mobile already uses:

   ```ts
   const resources = Object.fromEntries(
     Object.entries(translations).map(([lng, translation]) => [lng, { translation }]),
   );
   ```

3. **Add it to the picker.** [`src/components/LocaleSwitcher.tsx`](../app/frontend/src/components/LocaleSwitcher.tsx) hardcodes its `<option>` list. Add the new one with its **endonym** — the language's name in itself (`Deutsch`, not `German`).

4. Run `pnpm --filter frontend check:i18n`.

### Mobile

1. **Translate every key** in `src/lib/i18n/translations.json` — all 67, same rule.

2. **Add it to the picker.** [`app/mobile/components/LocaleSwitcher.tsx`](../app/mobile/components/LocaleSwitcher.tsx) hardcodes its `<Picker.Item>` list. See [drift item D2](#d2-the-mobile-locale-picker-only-offers-english) — this picker currently offers only English, so adding a locale here means adding the missing `es` and `fr` items too.

3. No bootstrap edit is required; `resources` is derived from the JSON.

4. Run `pnpm --filter mobile check:i18n`.

### Both clients

- Use the **BCP 47 code** (`de`, `pt-BR`, `zh-Hans`). Match whatever `Intl` expects, since the same string is passed to the formatters in §6.
- Selection persists to `localStorage` under `i18nextLng` on both clients, and `fallbackLng` is `en` on both.
- **RTL locales (Arabic, Hebrew, Farsi) need layout work beyond the dictionary** — direction handling on the web and `I18nManager.forceRTL` on mobile. Neither client has any RTL support today. Do not add an RTL locale without that work.

---

## 6. Pluralization, interpolation, and formatting

### Interpolation

Use `i18next`'s `{{name}}` syntax and pass values as the second argument to `t()`:

```json
{ "totalFee": "Total fee: {{totalFee}} XLM" }
```

```tsx
t('totalFee', { totalFee: formatNumber(fee, i18n.language) })
```

Rules:

- **Placeholder names are part of the key's contract.** Every locale of a key must use the same placeholder names — a translator who renames `{{hopCount}}` produces a silently empty slot.
- **Word order may change; placeholders may move.** That is the point of interpolation — never build a sentence by concatenating `t()` fragments.
- **`escapeValue` is `false` on both clients.** i18next does no HTML-escaping of interpolated values. React escapes on render, so this is safe for normal use, but never feed an interpolated result into `dangerouslySetInnerHTML`.
- **Interpolate formatted values, not raw ones.** Format the number or date first (below), then pass the string in.

Keys using interpolation today: `profileCustomizationDescription`, `noPathsFound`, `payReceive`, `hops`, `estimatedNetworkFee`, `quoteExpiresIn`, `totalFee`, `latency`.

### Pluralization

**Neither dictionary uses plurals today** — there is not a single `_one` / `_other` key on either client. `hops` is `"{{hopCount}} hops"`, which is wrong at 1.

When you add a countable string, use `i18next`'s suffix convention rather than an `if`:

```json
{
  "en": { "hops_one": "{{count}} hop",  "hops_other": "{{count}} hops" },
  "es": { "hops_one": "{{count}} salto", "hops_other": "{{count}} saltos" },
  "fr": { "hops_one": "{{count}} saut",  "hops_other": "{{count}} sauts" }
}
```

```tsx
t('hops', { count: hopCount })
```

Notes:

- The variable **must** be named `count`; that is what i18next reads to select the plural form.
- Plural categories are per-language. `en`, `es`, and `fr` need `_one` and `_other`; other languages need more (`_zero`, `_few`, `_many`). Add exactly the categories the language uses.
- **The parity checks compare key names literally**, so `hops_one` and `hops_other` are two independent keys. Every locale must carry the full set it needs, or CI fails. Migrating an existing key to plural form means updating both clients if it is shared.

### Formatting amounts and dates

**Never put a formatted number, currency, or date into the dictionary.** Separators, currency placement, and date order are locale properties, not translations. Keep the dictionary to the surrounding words and interpolate the formatted value.

The frontend has helpers in [`src/lib/formatting.ts`](../app/frontend/src/lib/formatting.ts). All take an optional locale and fall back to `navigator.language`, then `en-US`:

| Helper | Use for |
|---|---|
| `formatNumber(value, locale)` | Counts and plain quantities. Preserves up to 20 fractional digits and trims trailing zeros — safe for 7-decimal Stellar amounts, which `Intl.NumberFormat` would otherwise round. |
| `formatAssetAmount(value, asset, locale)` | On-chain amounts with a ticker: `1 234,5678 USDC`. |
| `formatCurrency(value, currency, locale)` | Fiat, 2 decimals, locale-correct symbol placement. |
| `formatDate(value, locale)` / `formatDateTime(value, locale)` | Dates and timestamps, `dateStyle: 'medium'`. |
| `getActiveLocale(locale)` | Canonicalise a locale string before passing it to `Intl` directly. |

Always pass the active locale explicitly — `const { i18n } = useTranslation()`, then `formatDate(value, i18n.language)`. Omitting it silently reads the browser locale, which is not necessarily the locale the user selected in the app.

Two gaps to be aware of:

- **Mobile has no formatting helpers at all.** There is no `formatting.ts` under `app/mobile`. Mobile code that needs a formatted amount or date should port these helpers rather than reimplement them ad hoc — see [drift item D4](#d4-formatting-helpers-are-frontend-only-and-inconsistently-used).
- **Much of the frontend bypasses them.** Roughly two dozen call sites hardcode `toLocaleString("en-US")` / `toLocaleDateString("en-US")` — including the developer settings, audit log, marketplace listing, and deployment panels. Those render US-formatted output regardless of the selected locale. Replacing a hardcoded `"en-US"` with a `formatting.ts` helper is a good first localization contribution.

---

## 7. Known drift — the current starting point

Everything below is true of the tree as it stands. Treat this section as the backlog, not as background.

### D1. The mobile i18n bootstrap import is broken

[`app/mobile/app/_layout.tsx:15`](../app/mobile/app/_layout.tsx#L15) reads:

```ts
import "../../src/lib/i18n";
```

From `app/mobile/app/`, `../..` resolves to `app/` — so the path is `app/src/lib/i18n`, which does not exist. The correct path is `../src/lib/i18n`, and no `tsconfig` alias covers the current form (`@/*` maps to `./*` relative to `app/mobile`).

**Consequence:** the `i18next` instance is never initialised at app start. `useTranslation()` still returns a `t` function, so nothing crashes — every call just returns the raw key name. The mobile dictionary is effectively inert at runtime, and the parity check cannot detect this because it only reads the JSON.

**Fix:** change the path to `../src/lib/i18n`. Verify by confirming a screen renders `Dashboard` rather than `dashboard`.

### D2. The mobile locale picker only offers English

[`app/mobile/components/LocaleSwitcher.tsx`](../app/mobile/components/LocaleSwitcher.tsx) contains a single `<Picker.Item label="English" value="en" />` followed by `{/* Add more languages later */}`. The mobile dictionary carries complete `es` and `fr` translations that **no user can select**. The frontend picker offers all three.

**Fix:** add `es` and `fr` items, or derive the list from `Object.keys(translations)` so the picker cannot drift from the dictionary again.

### D3. The two dictionaries have diverged in size and content

| | Frontend | Mobile |
|---|---|---|
| Keys per locale | 129 | 67 |
| Locales | `en`, `es`, `fr` | `en`, `es`, `fr` |
| Shared keys | **49** | **49** |
| Client-only keys | 80 | 18 |

Each client is internally at parity — all three locales carry the same key set. The drift is **between** clients, and it is not merely additive: **17 of the 49 shared keys have different English text on the two clients.**

| Key | Frontend `en` | Mobile `en` |
|---|---|---|
| `networkError` | Network error when calling preflight. | Network error calling preflight. |
| `destinationRequired` | Destination is required. | Destination address is required. |
| `recipientAssetDescription` | Asset that the recipient receives. | Same as the amount currency above — what lands in the receiver's account after the path executes. |
| `allowedSourceAssets` | Allowed source assets | Allowed source assets (payers) |
| `allowedSourceAssetsDescription` | Assets the payer can send from. | Payers may use any of the selected assets; Horizon suggests paths and send amounts. |
| `noPathsFound` | No paths found on `{{horizonUrl}}`. Try a different amount or asset mix. | No paths found for this combination on `{{horizonUrl}}`. Try other source assets or a smaller amount. |
| `payReceive` | Pay `{{sourceAmount}}` `{{sourceAsset}}` → Receive … | Pay `{{sourceAmount}}` (`{{sourceAsset}}`) → receive … |
| `hops` | `{{hopCount}}` hops | Hops: `{{hopCount}}` |
| `sorobanPreflight` | Soroban preflight | Soroban preflight (composer) |
| `sorobanPreflightDescription` | Run a simulation before sharing the payment link. | Runs the same simulation as `POST /transactions/compose` with `health_check` on `QUICKEX_CONTRACT_ID`. |
| `sourceAccountPlaceholder` | Source account public key (G...) | Source account G… (funded, for sequence) |
| `runPreflight` | Run preflight | Run preflight simulation |
| `simulationOk` | Simulation succeeded. | Simulation OK — fees estimated. |
| `totalFee` | Total fee: `{{totalFee}}` XLM | Total fee (incl. resource): `{{totalFee}}` XLM |
| `latency` | Latency: `{{latency}}` ms | Latency `{{latency}}` ms |
| `instantPaymentsDesc` | Generate payment links instantly with advanced path payment support. | Receive USDC, XLM, or any Stellar asset directly to your self-custody wallet. |

Two patterns are visible, and they need different treatment:

- **Cosmetic** (`latency`, `hops`, `networkError`, `runPreflight`) — pick one wording and apply it to both. Mechanical.
- **Substantively different copy** (`sorobanPreflightDescription`, `recipientAssetDescription`, `allowedSourceAssetsDescription`, `instantPaymentsDesc`) — mobile carries developer-facing detail that the frontend deliberately does not. These are arguably not the same string. **Decide per key: converge on shared wording, or split into two client-specific keys.** Do not silently overwrite one with the other; the mobile copy references implementation details a web user has no context for.

Note that the `es` and `fr` values follow their own client's `en`, so each divergence above is really three.

### D4. Formatting helpers are frontend-only and inconsistently used

`formatting.ts` exists only on the frontend, and much of the frontend does not use it — around two dozen call sites hardcode `"en-US"` (developer settings, audit logs, marketplace listings, activity feed, OG image route) or call `toLocaleString()` with no locale at all. Mobile has no helpers to bypass.

**Fix, in order:** replace hardcoded `"en-US"` call sites with the helpers, threading `i18n.language` through; then port `formatting.ts` to mobile — ideally by extracting it somewhere both clients can consume rather than copying it.

### D5. No cross-client parity tooling

The two `check-i18n-parity.mjs` scripts are near-identical, differ only in strictness on dead keys (frontend fails, mobile warns), and neither knows the other client exists. Nothing would have caught D3.

**Fix:** a third check asserting that keys present in both dictionaries carry identical `en` values, with an explicit allowlist for keys intentionally worded differently. Until that exists, the checklist in §4 is the only guard.

### D6. The mobile README's shared-key inventory is manually maintained

[`app/mobile/src/lib/i18n/README.md`](../app/mobile/src/lib/i18n/README.md) lists the shared and mobile-only keys by hand. Its inventory is currently **accurate** — all 49 shared keys and 18 mobile-only keys are correctly listed — but it will silently rot on the next change, and it already contains one stale pointer: it says the web dictionary lives in `app/frontend/src/lib/i18n.ts`, which now holds only the bootstrap. The strings moved to `src/lib/i18n/translations.json`.

If you change the shared-key set, update that list in the same PR.
