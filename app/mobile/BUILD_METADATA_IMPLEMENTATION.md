# Build Metadata Panel - Implementation Guide

## Overview
This implementation adds a read-only metadata panel to the QuickEx mobile app's settings screen, allowing contributors and QA teams to quickly verify build information without exposing sensitive data.

## What Was Implemented

### 1. **Utility Functions** (`src/utils/build-metadata.ts`)
- `getBuildMetadata()`: Extracts and formats build information from app configuration
- `formatEnvironment()`: Converts environment strings to human-readable format
- `formatNetwork()`: Converts network strings to human-readable format
- `getMetadataLabel()`: Returns display labels for metadata fields

**Metadata Fields Captured:**
- App Version (from package.json)
- Build Number (from CI/build system)
- Git Branch (extracted from BUILD_TAG if available)
- Git Commit (extracted from BUILD_TAG if available)
- Environment (production/staging/dev)
- Network (testnet/mainnet)

### 2. **Clipboard Utilities** (`src/utils/clipboard.ts`)
- `copyToClipboard()`: Copies text to clipboard with success/error handling
- `formatMetadataForSharing()`: Formats metadata as readable text for sharing

### 3. **BuildMetadataPanel Component** (`src/components/BuildMetadataPanel.tsx`)
A React Native component featuring:
- **CopyableMetadataRow**: Individual rows with tap-to-copy functionality
  - Shows "Copied" feedback for 2 seconds after copying
  - Copy icon changes to checkmark on success
  - Uses monospace font for code values
- **BuildMetadataPanel**: Main panel with:
  - All 6 metadata fields
  - Section header with description
  - "Copy All Metadata" button for bulk copying
  - Theme-aware styling matching QuickEx design system
  - Elevation and border for visual separation

### 4. **SettingsScreen Integration** (`src/screens/SettingsScreen.tsx`)
- Imported `BuildMetadataPanel` component
- Positioned after Danger Zone section, before version text
- Seamlessly integrated with existing settings layout

### 5. **Comprehensive Tests**
Three test files ensure reliability:
- **`__tests__/utils/build-metadata.test.ts`**: 16 tests covering:
  - Metadata extraction (all fields present and non-empty)
  - Environment formatting
  - Network formatting
  - Label generation
  
- **`__tests__/utils/clipboard.test.ts`**: 7 tests covering:
  - Successful clipboard copy
  - Success callback execution
  - Error handling
  - Metadata formatting
  
- **`__tests__/components/BuildMetadataPanel.test.tsx`**: 8 tests covering:
  - Component rendering
  - Field display
  - Metadata value display
  - Environment/network formatting
  - Snapshot testing

## How to Test

### Manual Testing Steps

1. **Install and run the mobile app**:
   ```bash
   cd app/mobile
   npx react-native run-ios    # For iOS
   # or
   npx react-native run-android # For Android
   ```

2. **Navigate to Settings**:
   - Open the app
   - Go to Settings screen (usually via navigation menu)
   - Scroll down past "Danger Zone" section

3. **Verify Build Metadata Panel displays**:
   - Should see "Build Metadata" section header
   - Should see description: "Tap any field to copy. Share this info when reporting issues."
   - Should see 6 metadata rows:
     - App Version: `1.0.0`
     - Build Number: (your build number from CI or config)
     - Git Branch: (branch name or "Unknown" if not set)
     - Git Commit: (short commit hash or "Unknown" if not set)
     - Environment: `Production` | `Staging` | `Development`
     - Network: `Testnet` | `Mainnet`

4. **Test Copy-to-Clipboard**:
   - Tap any metadata field
   - Should show "✓ Copied" indicator for 2 seconds
   - Copy icon should change to checkmark
   - Paste into a note app to verify content was copied

5. **Test Copy All**:
   - Tap "Copy All Metadata" button
   - Should see success alert: "Success - All metadata copied to clipboard"
   - Paste and verify format shows all fields

### Automated Testing

1. **Run unit tests**:
   ```bash
   cd app/mobile
   pnpm test
   # or with npm
   npm test
   ```

2. **Run specific test files**:
   ```bash
   pnpm test -- build-metadata.test.ts
   pnpm test -- clipboard.test.ts
   pnpm test -- BuildMetadataPanel.test.tsx
   ```

3. **Generate test coverage**:
   ```bash
   pnpm test -- --coverage
   ```

### Verification Checklist

- [ ] Build Metadata panel renders without crashes
- [ ] All 6 metadata fields display correctly
- [ ] Values match your build configuration
- [ ] Copy-to-clipboard works for individual fields
- [ ] "Copy All" button works
- [ ] Copied text feedback displays for 2 seconds
- [ ] Panel styling matches app theme (light/dark)
- [ ] No sensitive data is exposed (API keys, etc.)
- [ ] All unit tests pass
- [ ] Snapshot tests match current implementation

### Testing Different Environments

To test across different build configurations, set environment variables before building:

```bash
# Build for staging
APP_ENV=staging STELLAR_NETWORK=testnet pnpm build:mobile

# Build for production
APP_ENV=production STELLAR_NETWORK=mainnet pnpm build:mobile

# Build for development
APP_ENV=dev STELLAR_NETWORK=testnet pnpm build:mobile
```

The panel will automatically display the correct values based on the build configuration.

## File Structure

```
app/mobile/
├── src/
│   ├── components/
│   │   └── BuildMetadataPanel.tsx          (NEW)
│   ├── utils/
│   │   ├── build-metadata.ts               (NEW)
│   │   └── clipboard.ts                    (NEW)
│   └── screens/
│       └── SettingsScreen.tsx              (MODIFIED - added import & component)
├── __tests__/
│   ├── components/
│   │   └── BuildMetadataPanel.test.tsx     (NEW)
│   └── utils/
│       ├── build-metadata.test.ts          (NEW)
│       └── clipboard.test.ts               (NEW)
```

## Design System Compliance

The component uses QuickEx's token-based design system:
- **Colors**: Automatically adapts to light/dark/custom themes
- **Typography**: Uses 13-14px sizes, monospace for code
- **Spacing**: 24px section margin, 16px padding
- **Elevation**: surfaceElevated container with subtle border
- **Accessibility**: Clear contrast ratios, readable font sizes

## Performance Considerations

- Component is lightweight and re-renders only when metadata changes
- No unnecessary API calls or network requests
- Clipboard operations are async-safe with error handling
- Copy feedback is optimized with 2-second timeout

## Security & Privacy

✅ **No Sensitive Data Exposed**:
- No API keys or secrets displayed
- No wallet addresses or tokens
- Git branch/commit are non-sensitive build info
- No user PII

✅ **Data Flow**:
- All data sourced from build-time configuration
- No runtime data collection
- Copy operations stay on-device

## Future Enhancements

Potential improvements for future iterations:
1. Add contract version/address information
2. Support for feature flags status
3. Last build date/time
4. Build duration information
5. Developer mode toggle (if needed)
6. QR code generation for build metadata

## Troubleshooting

### Metadata shows "Unknown" for branch/commit
- **Cause**: BUILD_TAG not set in CI/build configuration
- **Solution**: Ensure `GIT_TAG` or `GITHUB_REF_NAME` environment variable is set
- **Expected Format**: `branch-name-abc1234def5678`

### Copy-to-clipboard fails silently
- **Cause**: expo-clipboard not properly installed
- **Solution**: Run `pnpm install` to ensure all dependencies are installed
- **Check**: Verify `expo-clipboard` is in package.json

### Tests fail or don't run
- **Cause**: Dependencies not installed
- **Solution**: Run `pnpm install` from app/mobile directory
- **Check**: Verify jest.config.js exists and is properly configured

## Support

For issues or questions about the implementation:
1. Check the test files for usage examples
2. Review component inline documentation
3. Refer to the QuickEx design system tokens in `src/theme/tokens.ts`
4. Check existing settings components for patterns

---

**Created**: June 26, 2026
**Branch**: feat/mobile-build-metadata-panel
**Status**: Complete and ready for testing
