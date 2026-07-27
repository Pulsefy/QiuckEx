# Mobile Release Checklist

This checklist supports the internal testing build pipeline for QuickEx Mobile.

## Release Pipeline
- [ ] Verify `.github/workflows/mobile-release.yml` exists and triggers on release tags `v*`
- [ ] Ensure `EAS_TOKEN` is configured in GitHub repository secrets
- [ ] Confirm `app/mobile/eas.json` contains `dev`, `staging`, and `production` internal build profiles
- [ ] Confirm build job does not print secrets or credentials in logs

## Build Metadata
- [ ] Confirm the app shows version and build metadata in Settings
- [ ] Confirm the app displays the selected build environment (`dev`, `staging`, `production`)
- [ ] Confirm the app displays the target network (`testnet` or `mainnet`)
- [ ] On release tags, make sure production builds are generated for both Android and iOS

## Permissions
- [ ] Camera permission only for QR scanning
- [ ] Local authentication permission only for wallet protection and unlocking secure data
- [ ] Notifications permission only for push and badge updates
- [ ] Background fetch permission only for sync activity and not for unnecessary telemetry

## Privacy Review
- [ ] No sensitive keys or secrets are embedded in mobile builds
- [ ] Supabase anonymous keys are used only for public requests and not for private data
- [ ] Wallet keys remain on-device and are never transmitted to backend services
- [ ] Data transmitted over the network is encrypted and sent only to approved endpoints
- [ ] User transaction history is treated as private and not shared with third parties without consent

## QA Verification
- [ ] Install internal build on Android and verify the correct environment shows in-app
- [ ] Install internal build on iOS and verify the correct environment and network display
- [ ] Verify the release tag or build metadata is visible if present
- [ ] Confirm the app behaves normally in the selected network environment
