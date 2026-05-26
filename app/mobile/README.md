# QuickEx Mobile App (Expo)

This is the Expo-based mobile application for the QuickEx platform, a privacy-focused payment link service built on the Stellar blockchain.

## Getting Started

### Prerequisites

- Node.js 18+
- pnpm
- Expo Go (on your mobile device) or a simulator/emulator

### Installation

1. Install dependencies from the root:
   ```bash
   pnpm install
   ```

### Running the App

Run the development server:
```bash
pnpm turbo run dev --filter=mobile
```

This will start the Expo CLI. You can then scan the QR code with Expo Go or press `i` for iOS / `a` for Android to open in an emulator.

## Project Structure

- `app/`: Expo Router pages (index, wallet-connect, layout).
- `components/`: Reusable UI components.
- `constants/`: App constants and theme.
- `hooks/`: Custom React hooks.

## Tech Stack

- **Framework**: Expo (React Native)
- **Navigation**: Expo Router (File-based)
- **Styling**: React Native StyleSheet
- **Blockchain**: Stellar SDK (planned)
- **Wallet**: WalletConnect integration (planned)

## Testing

Run unit tests:
```bash
pnpm --filter=mobile test
```

## Internal Release Builds

Internal testing builds for Android and iOS are produced using EAS. The pipeline is configured in `./.github/workflows/mobile-release.yml` and supports `dev`, `staging`, and `production` build profiles.

- Ensure `EAS_TOKEN` is set in the repository secrets.
- Release tags matching `v*` generate production internal artifacts automatically.
- Build metadata and environment labels are surfaced in the app Settings screen.
- For release readiness and privacy review, see `RELEASE_CHECKLIST.md`.

## Universal Links / App Links

QuickEx deep-link verification files now live in:

- `app/frontend/public/.well-known/apple-app-site-association`
- `app/frontend/public/.well-known/assetlinks.json`

Before production release, replace these placeholders with real values:

- `TEAM_ID.com.pulsefy.quickex` in the AASA file.
- `REPLACE_WITH_RELEASE_CERT_SHA256_FINGERPRINT` in `assetlinks.json`.
