# Universal Links and App Links Testing Guide

## Overview

This guide provides step-by-step instructions for contributors to test Universal Links (iOS) and App Links (Android) implementation for QuickEx payment links.

## Prerequisites

### For iOS Testing
- macOS with Xcode installed
- Physical iOS device (Universal Links don't work on simulator)
- Apple Developer account
- Test device added to Apple Developer account
- QuickEx iOS app installed on device

### For Android Testing
- Android physical device or emulator
- Android Studio installed
- QuickEx Android app installed on device
- Google account for Digital Asset Links verification

### General Requirements
- Access to QuickEx backend API
- Valid SSL certificate on domain
- Admin access to update verification files
- Code signing certificates for both platforms

## Quick Verification (5 Minutes)

### 1. Verify Files are Accessible

Check that the verification files are publicly accessible:

```bash
# Apple App Site Association
curl -I https://quickex.to/.well-known/apple-app-site-association
# Expected: HTTP/2 200, Content-Type: application/json

# Android Asset Links
curl -I https://quickex.to/.well-known/assetlinks.json
# Expected: HTTP/2 200, Content-Type: application/json
```

### 2. Verify File Content

```bash
# Check Apple AASA file
curl https://quickex.to/.well-known/apple-app-site-association

# Check Android assetlinks.json
curl https://quickex.to/.well-known/assetlinks.json
```

### 3. Test URL in Browser

Open these URLs in your browser:
- `https://quickex.to/username/test/amount/10`
- `https://quickex.to/username/test/amount/10/XLM`
- `https://quickex.to/username/test/amount/10/XLM/testmemo`

Expected: Page loads successfully (web fallback)

## iOS Universal Links Testing

### Step 1: Configure Xcode Project

1. **Open your iOS project in Xcode**
2. **Select your app target**
3. **Go to "Signing & Capabilities" tab**
4. **Add "Associated Domains" capability**:
   - Click "+ Capability"
   - Select "Associated Domains"
   - Add the following domains:
     ```
     applinks:quickex.to
     applinks:staging.quickex.to
     applinks:preview.quickex.to
     ```

### Step 2: Update Team ID

1. **Get your Apple Developer Team ID**:
   - Go to [Apple Developer Account](https://developer.apple.com/account)
   - Your Team ID is a 10-character alphanumeric string

2. **Update the AASA file**:
   - Edit `app/frontend/public/.well-known/apple-app-site-association`
   - Replace `TEAM_ID` with your actual Team ID
   - Example: `ABC1234567.com.pulsefy.quickex`

### Step 3: Build and Install App

```bash
# Navigate to mobile directory
cd app/mobile

# Install dependencies
npm install

# Build for iOS
npx react-native run-ios
```

### Step 4: Test Universal Links

1. **Open Safari on your iOS device**
2. **Navigate to a payment link**:
   ```
   https://quickex.to/username/test/amount/10
   ```
3. **Expected behavior**:
   - App should open automatically
   - Payment screen should display
   - Parameters should be correctly parsed

### Step 5: Test Custom Scheme

1. **Open Safari on your iOS device**
2. **Navigate to custom scheme link**:
   ```
   quickex://username/test/amount/10
   ```
3. **Expected behavior**:
   - App should open automatically
   - Same behavior as Universal Links
   - Parameters should be correctly parsed

### Step 6: Verify Apple CDN

Use Apple's validation tool:
1. Go to [Apple App Search Validation Tool](https://search.developer.apple.com/appsearch-validation-tool/)
2. Enter your domain: `quickex.to`
3. Check CDN propagation status
4. Verify AASA file is correctly processed

### Step 7: Test Fallback

1. **Uninstall the QuickEx app**
2. **Open Safari and navigate to**:
   ```
   https://quickex.to/username/test/amount/10
   ```
3. **Expected behavior**:
   - Web page should load
   - No app open prompt should appear

## Android App Links Testing

### Step 1: Get SHA256 Fingerprint

**For Debug Build**:
```bash
keytool -list -v -keystore ~/.android/debug.keystore \
  -alias androiddebugkey -storepass android -keypass android
```

**For Release Build**:
```bash
keytool -list -v -keystore path/to/your/release.keystore \
  -alias your-alias
```

Copy the SHA256 fingerprint (remove colons, make uppercase).

### Step 2: Update Asset Links File

1. **Edit `app/frontend/public/.well-known/assetlinks.json`**
2. **Replace `PLACEHOLDER_SHA256_FINGERPRINT`** with your actual SHA256
3. **Example**:
   ```json
   "sha256_cert_fingerprints": [
     "14:6D:E9:83:C5:73:06:50:D2:0B:86:37:AA:2B:..."
   ]
   ```

### Step 3: Configure Android Manifest

Add to your `AndroidManifest.xml`:

```xml
<activity
    android:name=".MainActivity"
    android:launchMode="singleTask"
    android:label="@string/app_name"
    android:configChanges="keyboard|keyboardHidden|orientation|screenLayout|uiMode|screenSize|smallestScreenSize"
    android:windowSoftInputMode="adjustResize">

    <!-- App Links for https -->
    <intent-filter android:autoVerify="true">
        <action android:name="android.intent.action.VIEW" />
        <category android:name="android.intent.category.DEFAULT" />
        <category android:name="android.intent.category.BROWSABLE" />
        <data android:scheme="https" />
        <data android:host="quickex.to" />
        <data android:pathPattern="/username/.*" />
    </intent-filter>

    <!-- Custom Scheme -->
    <intent-filter>
        <action android:name="android.intent.action.VIEW" />
        <category android:name="android.intent.category.DEFAULT" />
        <category android:name="android.intent.category.BROWSABLE" />
        <data android:scheme="quickex" />
    </intent-filter>
</activity>
```

### Step 4: Build and Install App

```bash
# Navigate to mobile directory
cd app/mobile

# Install dependencies
npm install

# Build for Android
npx react-native run-android
```

### Step 5: Test App Links

1. **Open Chrome on your Android device**
2. **Navigate to a payment link**:
   ```
   https://quickex.to/username/test/amount/10
   ```
3. **Expected behavior**:
   - App should open automatically
   - Payment screen should display
   - Parameters should be correctly parsed

### Step 6: Test Custom Scheme

1. **Open Chrome on your Android device**
2. **Navigate to custom scheme link**:
   ```
   quickex://username/test/amount/10
   ```
3. **Expected behavior**:
   - App should open automatically
   - Same behavior as App Links
   - Parameters should be correctly parsed

### Step 7: Verify Digital Asset Links

Use Google's verification tool:
1. Go to [Digital Asset Links Generator](https://developers.google.com/digital-asset-links/tools/generator)
2. Enter your site domain: `quickex.to`
3. Enter your app package name: `com.pulsefy.quickex`
4. Enter your SHA256 fingerprint
5. Click "Test Digital Asset Links"
6. Verify the relationship is valid

### Step 8: Test Fallback

1. **Uninstall the QuickEx app**
2. **Open Chrome and navigate to**:
   ```
   https://quickex.to/username/test/amount/10
   ```
3. **Expected behavior**:
   - Web page should load
   - No app open prompt should appear

## Environment-Specific Testing

### Production (quickex.to)
1. Deploy verification files to production
2. Test with production app builds
3. Verify both platforms work correctly
4. Test fallback behavior

### Staging (staging.quickex.to)
1. Deploy verification files to staging
2. Test with staging app builds
3. Verify both platforms work correctly
4. Test fallback behavior

### Preview (preview.quickex.to)
1. Deploy verification files to preview
2. Test with preview app builds
3. Verify both platforms work correctly
4. Test fallback behavior

## Common Issues and Solutions

### iOS Issues

**Universal Links not opening app**:
- Check Associated Domains are correctly configured
- Verify Team ID matches your Apple Developer account
- Ensure AASA file is accessible via HTTPS
- Test on physical device (not simulator)
- Check Apple CDN propagation status

**AASA file not accessible**:
- Verify file is in `public/.well-known/` directory
- Check file permissions
- Ensure no file extension on AASA file
- Verify Content-Type is `application/json`

**CDN propagation delay**:
- Apple CDN may take 24-48 hours to propagate
- Use Apple's validation tool to check status
- Clear Safari cache on test device

### Android Issues

**App Links not opening app**:
- Verify SHA256 fingerprint matches signing key
- Check package name matches exactly
- Ensure `android:autoVerify="true"` is set
- Verify intent-filter configuration
- Test with both debug and release builds

**Asset Links file not accessible**:
- Verify file is in `public/.well-known/` directory
- Check file permissions
- Ensure valid JSON format
- Verify Content-Type is `application/json`

**Digital Asset Links verification failing**:
- Check SHA256 fingerprint format (no colons, uppercase)
- Verify package name matches exactly
- Ensure file is accessible via HTTPS
- Use Google's verification tool for debugging

## Testing Checklist

### Pre-Deployment
- [ ] Verification files are accessible
- [ ] Content-Type headers are correct
- [ ] Team ID/SHA256 fingerprints are configured
- [ ] Associated Domains/App Links configured in app
- [ ] Custom scheme handling implemented

### iOS Testing
- [ ] Universal Links open app on physical device
- [ ] Custom scheme opens app
- [ ] Both schemes route to same screen
- [ ] Parameters parsed correctly
- [ ] Error handling works
- [ ] Fallback to web works
- [ ] Apple CDN validation passes

### Android Testing
- [ ] App Links open app on device
- [ ] Custom scheme opens app
- [ ] Both schemes route to same screen
- [ ] Parameters parsed correctly
- [ ] Error handling works
- [ ] Fallback to web works
- [ ] Digital Asset Links verification passes

### Cross-Platform
- [ ] Behavior is consistent across platforms
- [ ] URL patterns work identically
- [ ] Error handling is consistent
- [ ] User experience is unified

## Automation

### Automated Tests

Create automated tests for URL parsing:

```typescript
// Example test for URL parsing
describe('Deep Link URL Parsing', () => {
  test('Universal Links and custom schemes parse identically', () => {
    const universalLink = 'https://quickex.to/username/test/amount/10/XLM/memo';
    const customScheme = 'quickex://username/test/amount/10/XLM/memo';
    
    const universalParams = parseURL(universalLink);
    const customParams = parseURL(customScheme);
    
    expect(universalParams).toEqual(customParams);
  });
});
```

### CI/CD Integration

Add verification to CI pipeline:
```yaml
# Example GitHub Actions step
- name: Verify Universal Links files
  run: |
    curl -f https://quickex.to/.well-known/apple-app-site-association
    curl -f https://quickex.to/.well-known/assetlinks.json
```

## Reporting Issues

When reporting issues, include:
1. Platform (iOS/Android)
2. Device model and OS version
3. App version and build number
4. URL tested
5. Expected vs actual behavior
6. Screenshots if applicable
7. Console logs if available
8. Verification file content (redact sensitive info)

## Additional Resources

- [Apple Universal Links Documentation](https://developer.apple.com/documentation/xcode/supporting-universal-links-in-your-app)
- [Android App Links Documentation](https://developer.android.com/training/app-links)
- [Digital Asset Links API](https://developers.google.com/digital-asset-links)
- [Apple App Search Validation Tool](https://search.developer.apple.com/appsearch-validation-tool/)
- [Digital Asset Links Generator](https://developers.google.com/digital-asset-links/tools/generator)

## Success Criteria

✅ All verification files are accessible and valid
✅ Universal Links open app on iOS when installed
✅ App Links open app on Android when installed
✅ Custom schemes work on both platforms
✅ Both schemes handle URLs identically
✅ Fallback to web page works when app not installed
✅ All automated tests pass
✅ Manual testing on physical devices successful
✅ Documentation is complete and accurate