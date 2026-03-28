# Mobile Multi-Asset Swap (Path Payments) Implementation

## Overview

This document describes the implementation of **in-app multi-asset swap** functionality for the QuickEx mobile app, enabling users to pay links using any asset they hold via Stellar's Path Payments.

## Architecture

The feature consists of **two main components**:

### 1. **Swap Options Discovery** (Backend ↔ Mobile)
- **Backend**: `LinksService.generateMetadata()` with `acceptedAssets` parameter returns `swapOptions`
- **Mobile**: `useSwapOptions` hook fetches available swap paths for all whitelisted assets
- **API**: `POST /links/metadata` accepts array of `acceptedAssets` and returns `PathPreviewRow[]`

### 2. **Swap Path Execution** (Mobile → Wallet → Stellar)
- **Mobile**: Builds Stellar URI with path payment parameters (`sendAsset`, `sendAmount`)
- **Wallet**: Handles PathPaymentStrictReceive transaction construction and signing
- **Stellar**: Executes swap with exact destination amount guarantee

## Implementation Details

### Files Created

1. **Services**
   - `services/link-metadata.ts` - Fetches link metadata with swap options
   - `services/path-payment.ts` - Utilities for path payment transaction building

2. **Hooks**
   - `hooks/use-swap-options.ts` - React hook for fetching and managing swap data

3. **Components**
   - `components/swap-asset-selector.tsx` - UI for selecting source asset and viewing rates
   - `components/swap-rate-details.tsx` - Displays exchange rates, path details, and slippage warnings

4. **Pages (Modified)**
   - `app/payment-confirmation.tsx` - Enhanced with multi-asset swap UI

### Data Flow

```
1. User Scans QR Code
   └─> Payment Link: quickex://username?amount=50&asset=USDC

2. Navigation to payment-confirmation.tsx
   └─> useSwapOptions Hook Triggered
       └─> Fetches /links/metadata with acceptedAssets=[XLM, USDC, AQUA, yXLM]
           └─> Backend computes paths for each asset
               └─> Returns swapOptions[]: [
                   { sourceAsset: XLM, sourceAmount: 200, rate: ..., hopCount: 1 },
                   { sourceAsset: USDC, sourceAmount: 50, rate: ..., hopCount: 0 },
                   { sourceAsset: AQUA, sourceAmount: 75, rate: ..., hopCount: 2 }
                 ]

3. Display Swap Asset Selector
   └─> User selects source asset (e.g., XLM)
       └─> SwapRateDetails shows exchange rate, slippage, path details

4. User Taps "Pay with Wallet"
   └─> Biometric/PIN Authentication
       └─> Opens Stellar URI with path payment params
           └─> web+stellar:pay?destination=username&amount=50&asset_code=USDC&sendAsset=XLM&sendAmount=200

5. External Wallet Handles Transaction
   └─> Wallet builds PathPaymentStrictReceive operation
       └─> User confirms and signs
           └─> Broadcasts to Stellar network
               └─> Stellar executes with intermediary swaps as needed
```

## Acceptance Criteria - Implementation Status

### ✅ Completed

1. **Users can select a different source asset to fulfill a payment request**
   - `SwapAssetSelector` component displays available source assets
   - Selection updates `selectedSwapPath` state
   - Wallet URI includes `sendAsset` and `sendAmount` parameters

2. **UI clearly displays the conversion rate before confirmation**
   - `SwapRateDetails` component shows:
     - Exchange rate (from path.rateDescription)
     - Source and destination amounts
     - Path visualization (intermediary assets)
     - Slippage percentage

3. **Show estimated exchange rates and slippage warnings**
   - Real exchange rates from backend `rateDescription`
   - Slippage calculated via `calculateSlippage()` function
   - Visual warnings when slippage > 2%
   - Slippage progress bar visualization

## Testing the Feature

### Manual Testing

1. **Setup**
   ```bash
   # Start backend
   cd app/backend
   pnpm dev
   
   # Start mobile app
   cd app/mobile
   pnpm start
   ```

2. **Test Multi-Asset Swap**
   - Create a payment link accepting multiple assets (e.g., USDC with acceptedAssets: [XLM, AQUA])
   - Scan link on mobile
   - Verify "Select Payment Asset" section appears
   - Verify exchange rates are displayed
   - Select XLM as payment asset
   - Verify slippage warning appears (if > 2%)
   - Verify "Pay with Wallet" opens correct Stellar URI

3. **Test Direct Payment (No Swap)**
   - Create link with asset but no acceptedAssets
   - Verify "Select Payment Asset" section does NOT appear
   - Verify standard "Pay with Wallet" works

### Unit Tests (Frontend)

```typescript
// Test useSwapOptions hook
test('fetches swap options when component mounts', async () => {
  // Verify fetchLinkMetadata is called with acceptedAssets
  // Verify swapOptions state updates correctly
});

// Test SwapAssetSelector component
test('renders available swap paths', () => {
  // Verify best paths are selected (lowest source amount)
  // Verify selection handler is called correctly
});

// Test SwapRateDetails component
test('displays slippage warnings correctly', () => {
  // Verify warning shows when slippage > 2%
  // Verify slippage percentage is calculated correctly
});

// Test path-payment utilities
test('calculateSlippage returns expected values', () => {
  // 0% for direct (hopCount=0)
  // ~0.1% per hop for others
  // Capped at 5%
});
```

### Integration Tests

1. **Backend API**: Verify `/links/metadata` returns correct swapOptions
2. **Wallet Integration**: Confirm Stellar URI parameters are formatted correctly
3. **End-to-End**: Scan → Select Asset → Confirm → Wallet → Success

## Configuration

### Supported Assets (Hardcoded Whitelist)

```typescript
const SWAPPABLE_ASSETS = ["XLM", "USDC", "AQUA", "yXLM"];
```

These match the backend whitelist in `LinkMetadataRequestDto`.

### API Configuration

Mobile app reads API base URL from:
1. `EXPO_CONFIG.extra.apiUrl` (app.json)
2. `EXPO_PUBLIC_API_URL` environment variable
3. Falls back to `http://localhost:3000`

Configure in your environment:
```bash
# .env or app.json
EXPO_PUBLIC_API_URL=https://quickex-api.example.com
```

## Limitations & Future Work

### Current Limitations

1. **Wallet Delegation Only**: Transactions are built and signed by external wallets
   - No in-app private key management
   - User must have Stellar-compatible wallet installed

2. **Stellar URI Standard**: Relying on `sendAsset`/`sendAmount` parameters
   - Not all wallets support these parameters yet
   - May need fallback UX if wallet doesn't support path payments

3. **Fixed Asset Whitelist**: Only 4 assets supported
   - Can be extended by updating backend and mobile lists

### Future Enhancements

1. **In-App Transaction Building** (Wave 5)
   - Allow users to connect private keys or passkey
   - Build and sign path payment transactions in-app
   - Direct submission to Stellar network

2. **Dynamic Asset Discovery**
   - Fetch supported assets from verified-assets endpoint
   - Remove hardcoded whitelist

3. **Path Routing Optimization**
   - Return multiple best paths from backend
   - Let user choose between different route options
   - Show fees vs. rate tradeoffs

4. **Transaction Polling Enhancement**
   - Detect incoming path payment transactions
   - Show source asset in transaction history
   - Track multi-asset payments

## Backend Integration Points

### LinkMetadataRequestDto

```typescript
export interface LinkMetadataRequestDto {
  amount: number;
  asset: string;
  username: string;
  memo?: string;
  memoType?: string;
  acceptedAssets?: string[];  // Triggers path preview computation
  // ... other fields
}
```

### LinkMetadataResponseDto

```typescript
export interface LinkMetadataResponseDto {
  amount: string;
  asset: string;
  destination?: string;
  swapOptions?: PathPreviewRow[];  // Returned only if acceptedAssets provided
  // ... other fields
}
```

### PathPreviewRow

```typescript
export interface PathPreviewRow {
  sourceAmount: string;         // What user pays
  sourceAsset: string;          // User's asset
  destinationAmount: string;    // What recipient gets
  destinationAsset: string;     // Recipient's asset
  hopCount: number;             // Number of intermediary swaps
  pathHops: string[];           // Intermediate assets
  rateDescription: string;      // Human-readable rate (e.g., "1 USDC = 0.95 XLM")
}
```

## Security Considerations

1. **Input Validation**
   - Asset codes validated against whitelist
   - Amounts validated on both frontend and backend
   - Wallet URI properly escapes parameters

2. **Transaction Transparency**
   - User sees exact exchange rate before confirmation
   - Slippage warnings displayed for complex paths
   - Path details shown in SwapRateDetails

3. **Authentication**
   - Biometric/PIN required before opening wallet URI
   - Prevents accidental payments

## Code Examples

### Using the Feature Programmatically

```typescript
// Fetch swap options in a component
const { swapOptions, loading, error } = useSwapOptions(
  'recipient_username',
  50,
  'USDC',
  ['XLM', 'USDC', 'AQUA', 'yXLM']
);

// Build path payment URI
const stellarUri = `web+stellar:pay?destination=${username}&amount=50&asset_code=USDC&sendAsset=XLM&sendAmount=200`;

// Calculate slippage
import { calculateSlippage } from '@/services/path-payment';
const slippage = calculateSlippage('200', '50', 1); // ~0.1% for 1 hop
```

## Deployment Checklist

- [ ] Backend API returning swapOptions correctly
- [ ] Mobile API service configured for production backend
- [ ] Asset whitelist synchronized between backend and mobile
- [ ] Testing with real Stellar testnet wallets
- [ ] User documentation updated with new swap feature
- [ ] Analytics tracked for multi-asset payments
- [ ] Error handling tested for offline scenarios
- [ ] Slippage warnings tested with various path complexities
- [ ] UI tested on different device sizes and orientations

## Troubleshooting

### Swap Options Not Showing

**Symptom**: "Select Payment Asset" section not visible

**Diagnose**:
1. Check backend response has `swapOptions` array
2. Verify `acceptedAssets` sent to `/links/metadata` endpoint
3. Ensure at least one source asset differs from destination asset
4. Check mobile network connectivity

**Solution**:
- Force refresh by navigating away and back
- Check network tab in browser dev tools
- Verify backend logs for pathname routing errors

### "No Wallet Found" Error

**Symptom**: Alert appears when tapping "Pay with Wallet"

**Diagnose**:
1. Verify wallet app is installed
2. Check wallet supports `web+stellar:pay` scheme
3. Log the Stellar URI being opened

**Solution**:
- Install a Stellar-compatible wallet (Stellar Expert, StellarX, etc.)
- Test with different wallets for compatibility
- Fallback to QR code display if URI scheme not recognized

### Slippage Warnings Too Aggressive

**Symptom**: Warnings show for low-slippage paths (< 1%)

**Diagnose**:
- Check `calculateSlippage()` formula vs. actual market rates
- Verify backend `rateDescription` reflects true rates

**Solution**:
- Adjust warning threshold in `SwapRateDetails` component
- Use real-time rate data from Horizon for more accurate slippage
- Consider implementing CEX comparison rates

---

**Version**: 1.0  
**Status**: ✅ Ready for Testing  
**Last Updated**: 2026-03-28
