# Universal Links and App Links Verification Assets

This directory contains the verification files required for iOS Universal Links and Android App Links to work properly with QuickEx payment links.

## Files

### `apple-app-site-association`
- **Purpose**: Apple App Site Association file for iOS Universal Links
- **Format**: JSON (no file extension)
- **Path**: `/.well-known/apple-app-site-association`
- **Content**: Defines which URL paths should open the QuickEx app on iOS

### `assetlinks.json`
- **Purpose**: Android Digital Asset Links file for Android App Links
- **Format**: JSON
- **Path**: `/.well-known/assetlinks.json`
- **Content**: Defines the relationship between the website and Android app

## Environment-Specific Configuration

The verification files need to be configured for each environment:

### Production
- **Domain**: `quickex.to`
- **iOS Team ID**: Replace `TEAM_ID` in apple-app-site-association
- **Android SHA256**: Replace `PLACEHOLDER_SHA256_FINGERPRINT` in assetlinks.json

### Staging
- **Domain**: `staging.quickex.to`
- Uses same app IDs but served from staging domain

### Preview
- **Domain**: `preview.quickex.to`
- Uses same app IDs but served from preview domain

## URL Patterns Supported

The Universal Links/App Links are configured to handle:
- `/username/*` - Any username-based payment link
- `/username/*/amount/*` - Payment links with specific amount
- `/username/*/amount/*/*` - Payment links with amount and asset
- `/username/*/amount/*/*/*` - Payment links with amount, asset, and memo

## Setup Instructions

### iOS (Universal Links)

1. **Configure Team ID**:
   - Replace `TEAM_ID` in `apple-app-site-association` with your actual Apple Developer Team ID
   - Format: 10-character alphanumeric string

2. **Enable Associated Domains in Xcode**:
   - Open your iOS project in Xcode
   - Select your app target
   - Go to "Signing & Capabilities"
   - Add "Associated Domains" capability
   - Add: `applinks:quickex.to`
   - Add staging: `applinks:staging.quickex.to`
   - Add preview: `applinks:preview.quickex.to`

3. **Verify file is accessible**:
   - `https://quickex.to/.well-known/apple-app-site-association`
   - Must return JSON with correct Content-Type: `application/json`

### Android (App Links)

1. **Get SHA256 Fingerprint**:
   ```bash
   # For debug builds
   keytool -list -v -keystore ~/.android/debug.keystore -alias androiddebugkey -storepass android -keypass android
   
   # For release builds
   keytool -list -v -keystore path/to/your/release.keystore -alias your-alias
   ```

2. **Update assetlinks.json**:
   - Replace `PLACEHOLDER_SHA256_FINGERPRINT` with your actual SHA256 fingerprint
   - Remove colons and make uppercase

3. **Enable App Links in Android Manifest**:
   ```xml
   <intent-filter android:autoVerify="true">
       <action android:name="android.intent.action.VIEW" />
       <category android:name="android.intent.category.DEFAULT" />
       <category android:name="android.intent.category.BROWSABLE" />
       <data android:scheme="https" />
       <data android:host="quickex.to" />
       <data android:pathPattern="/username/.*" />
   </intent-filter>
   ```

4. **Verify file is accessible**:
   - `https://quickex.to/.well-known/assetlinks.json`
   - Must return JSON with correct Content-Type: `application/json`

## Testing

### iOS Testing
1. Build and install the app on a physical device (not simulator)
2. Open Safari and navigate to a payment link: `https://quickex.to/username/test/amount/10`
3. The app should open automatically
4. If not, check:
   - Associated Domains are correctly configured
   - apple-app-site-association is accessible and valid
   - App is signed with correct Team ID

### Android Testing
1. Build and install the app on a physical device
2. Open Chrome and navigate to a payment link: `https://quickex.to/username/test/amount/10`
3. The app should open automatically
4. If not, check:
   - App Links are correctly configured in manifest
   - assetlinks.json is accessible and valid
   - SHA256 fingerprint matches the app's signing key

## Troubleshooting

### iOS Universal Links Not Working
- Ensure the file is accessible via HTTPS
- Verify the Content-Type is `application/json` (not `application/octet-stream`)
- Check that the Team ID matches your Apple Developer account
- Make sure Associated Domains are enabled in Xcode
- Test on a physical device (simulator doesn't support Universal Links)

### Android App Links Not Working
- Ensure the file is accessible via HTTPS
- Verify the SHA256 fingerprint matches your signing key
- Check that the package name matches exactly
- Make sure `android:autoVerify="true"` is set in the intent filter
- Test on a physical device

## Verification Tools

### Apple
- Use Apple's CDN validation tool: https://search.developer.apple.com/appsearch-validation-tool/
- Check CDN propagation status

### Android
- Use Google's Digital Asset Links tool: https://developers.google.com/digital-asset-links/tools/generator
- Verify the relationship between website and app

## Security Notes

- Both files must be served over HTTPS
- Files should not contain sensitive information
- Keep SHA256 fingerprints private until deployment
- Regularly verify that the files are accessible and valid