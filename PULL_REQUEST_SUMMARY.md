# Initialize app/mobile: React Native App with Navigation and WalletConnect Placeholder

**Closes #3**

## Description
This PR bootstraps the React Native application in `app/mobile` using Expo. It sets up the foundational navigation structure with two screens (Home and WalletConnect), adds essential documentation, and configures the project for the monorepo environment.

## Changes
- **Initialized Expo Project**: Created a new Expo app in `app/mobile`.
- **Navigation**: Configured Expo Router (file-based navigation) in `app/mobile/app`.
- **Screens**:
  - `HomeScreen` (`app/index.tsx`): Main entry point with platform overview.
  - `WalletConnectScreen` (`app/wallet-connect.tsx`): Placeholder for future wallet integration.
- **Documentation**:
  - Added `app/mobile/README.md` with setup and running instructions.
  - Added `app/mobile/CONTRIBUTING.md` for development guidelines.
- **Configuration**:
  - Updated `package.json` scripts.
  - Configured `tsconfig.json` for TypeScript.
  - Fixed TypeScript definitions for testing (`react-test-renderer`).
- **Testing**: Added Jest configuration and a basic snapshot test for the Home screen.

## Verification Results

### Automated Tests
Ran `pnpm test` in `app/mobile`:
```text
 PASS  __tests__/Home.test.tsx
  <HomeScreen />
    ✓ renders correctly (14 ms)

Test Suites: 1 passed, 1 total
Tests:       1 passed, 1 total
Snapshots:   0 total
Time:        1.184 s
```

### Manual Verification
1. Run the development server:
   ```bash
   pnpm turbo run dev --filter=mobile
   ```
2. Open in iOS Simulator or Android Emulator (or Expo Go).
3. Verify `HomeScreen` renders.
4. Click "Connect Wallet" to navigate to `WalletConnectScreen`.
5. Verify "Go Back" functionality works.

## Directory Tree
```text
app/mobile
├── README.md
├── CONTRIBUTING.md
├── package.json
├── app
│   ├── _layout.tsx
│   ├── index.tsx
│   └── wallet-connect.tsx
├── components
│   ├── ui
│   └── ...
└── __tests__
    └── Home.test.tsx
```

## Screenshots
| Home Screen | Wallet Connect Screen |
|:---:|:---:|
| ![Home Screen Setup](TODO_ATTACH_SCREENSHOT_HERE) | ![Wallet Connect Setup](TODO_ATTACH_SCREENSHOT_HERE) |
