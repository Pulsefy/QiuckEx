# Maestro E2E Tests

This directory contains Maestro flows for the QuickEx mobile app.

## Scan-to-Pay Flow

`scan-to-pay.yaml` covers **deep-link grammar and route resolution** for the
payment path: a well-formed payment link must resolve to the payment-confirmation
route, and a malformed one must be rejected.

### What it does not cover

Payment execution is out of scope. `payment-confirmation` gates its render on a
live contract-registry fetch (`hooks/useContractRegistry.ts`) and then hands off
to an external wallet app via URI. A bare CI emulator has neither a backend nor a
wallet, so the tap-through-to-receipt path cannot run here. Covering it needs
either a backend service in CI or an E2E stub mode in the app.

### Link grammar

The username is the URL **host** and `amount` is a **required query param**
(`utils/parse-payment-link.ts`):

```
quickex://<username>?amount=<n>&asset=<XLM|USDC|AQUA|yXLM>&memo=<text>&privacy=<bool>
```

Note that `quickex://pay/<username>/<amount>` is **not** valid — it parses the
username as `pay` and finds no `amount`, and the link is rejected.

### Onboarding is a prerequisite

Deep links are queued, not routed, until onboarding completes — see
`canRouteDeepLink` in `app/_layout.tsx`. "Skip" only navigates; it does not mark
onboarding complete. Any flow that opens a link on fresh state must run
onboarding to the end first, which is why this flow taps through all four steps.

### Running locally

1. Install Maestro:

   ```bash
   curl -Ls "https://get.maestro.mobile.dev" | bash
   ```

2. Build the app and install it on an Android emulator or iOS simulator. The
   flow targets `to.quickex.app.dev`, which is the `APP_ENV=dev` package id
   (`app.config.ts`); a production build uses `to.quickex.app` and will not match.

3. Run the flow from the repository root:

   ```bash
   maestro test .maestro/scan-to-pay.yaml
   ```

## CI

The flow runs in the `maestro-tests` job of `.github/workflows/mobile-e2e.yml`.
On failure, Maestro artifacts are uploaded to GitHub Actions.
