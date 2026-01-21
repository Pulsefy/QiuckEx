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
