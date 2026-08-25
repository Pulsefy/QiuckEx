# Maestro E2E Tests

This directory contains Maestro flows for the QuickEx mobile app.

## Scan-to-Pay Flow

The `scan-to-pay.yaml` flow covers the primary payment path: QR scan → confirmation → receipt.

### Running locally

1. Install Maestro:

   ```bash
   curl -Ls "https://get.maestro.mobile.dev" | bash
   ```

2. Build the app and install it on an Android emulator or iOS simulator.

3. Run the flow from the `app/mobile` directory:

   ```bash
   maestro test ../../.maestro/scan-to-pay.yaml
   ```

The flow uses a deterministic deep link (`quickex://pay/...`) as the QR payload, so no physical QR code is required.

## CI

The flow runs in the `maestro-tests` job of `.github/workflows/mobile-e2e.yaml`. On failure, Maestro artifacts are uploaded to GitHub Actions.