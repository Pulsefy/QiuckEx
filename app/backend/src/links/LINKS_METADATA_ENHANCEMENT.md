# Links Metadata Enhancement Documentation

## Overview

The `/links/metadata` endpoint has been enhanced with richer validation rules and canonicalization features to provide more robust metadata generation for frontend consumption.

## New Features

### Enhanced Validation

#### 1. Stricter Asset Validation
- Assets are now validated against a whitelist using the `@IsStellarAsset` decorator
- Supported assets: XLM, USDC, AQUA, yXLM
- Invalid assets return `ASSET_NOT_WHITELISTED` error

#### 2. Username Pattern Validation
- Added `username` field with strict pattern validation
- Pattern: `^[a-z0-9][a-z0-9_-]{2,30}[a-z0-9]$|^[a-z0-9]{1,32}$`
- Rules:
  - 1-32 lowercase alphanumeric characters
  - May include hyphens and underscores
  - Cannot start or end with special characters
  - Reserved words blocked (admin, system, root, quickex)
- Normalized to lowercase automatically

#### 3. Stellar Public Key Validation
- Added `destination` field for Stellar account public keys
- Strict format validation: `^G[ABCDEFGHIJKLMNOPQRSTUVWXYZ234567]{55}$`
- 56 characters total (G + 55 base32 characters)

#### 4. Reference ID Validation
- Added `referenceId` field for custom tracking
- Pattern: `^[a-zA-Z0-9_-]{1,64}$`
- 1-64 alphanumeric characters, hyphens, or underscores

### Canonicalization Improvements

#### Asset Symbol Normalization
- Assets are normalized to their canonical format
- XLM → XLM (native)
- USDC → USDC (credit_alphanum4 with issuer)
- AQUA → AQUA (credit_alphanum4 with issuer)
- yXLM → yXLM (credit_alphanum4 with issuer)

#### Enhanced Canonical Format
The canonical format now includes all provided parameters:
```
amount=100.5000000&asset=USDC&memo=Payment+for+services&username=john_doe&destination=GA3F2...&ref=INV-12345
```

### Additional Metadata Fields

The response now includes enriched metadata for frontend consumption:

#### Asset Metadata
```json
{
  "metadata": {
    "assetType": "credit_alphanum4",
    "assetIssuer": "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN"
  }
}
```

#### Link Classification
```json
{
  "metadata": {
    "linkType": "username" | "private" | "standard"
  }
}
```

#### Security Level Indicator
```json
{
  "metadata": {
    "securityLevel": "low" | "medium" | "high"
  }
}
```

Security level is calculated based on:
- Low: Basic link (0-1 security features)
- Medium: Link with memo or expiration (1-2 security features)
- High: Link with multiple security features (3+ features)

#### Expiration Metadata
```json
{
  "metadata": {
    "isExpiring": true,
    "expiresInDays": 30
  }
}
```

## API Changes

### New Request Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `username` | string | Optional | Username for the payment link |
| `destination` | string | Optional | Destination Stellar account public key |
| `referenceId` | string | Optional | Custom reference ID for tracking |

### New Response Fields

| Field | Type | Description |
|-------|------|-------------|
| `username` | string/null | Normalized username |
| `destination` | string/null | Validated destination key |
| `referenceId` | string/null | Reference ID |
| `metadata` | object | Enhanced metadata with additional fields |

### Error Codes

New error codes have been added:
- `INVALID_USERNAME` - Username validation failed
- `USERNAME_RESERVED` - Username is reserved
- `INVALID_DESTINATION` - Invalid Stellar public key
- `INVALID_REFERENCE_ID` - Reference ID validation failed

## Examples

### Basic Request
```json
POST /links/metadata
{
  "amount": 100.5,
  "asset": "USDC",
  "memo": "Payment for services"
}
```

### Enhanced Request
```json
POST /links/metadata
{
  "amount": 100.5,
  "asset": "USDC",
  "memo": "Payment for services",
  "username": "john_doe123",
  "destination": "GA3F2N3N4KVZ255TM74J5J7N3N4KVZ255TM74J5J7N3N4KVZ255TM74J",
  "referenceId": "INV-12345",
  "privacy": true,
  "expirationDays": 30
}
```

### Response
```json
{
  "success": true,
  "data": {
    "amount": "100.5000000",
    "memo": "Payment for services",
    "memoType": "text",
    "asset": "USDC",
    "privacy": true,
    "expiresAt": "2026-03-24T12:00:00.000Z",
    "canonical": "amount=100.5000000&asset=USDC&memo=Payment+for+services&username=john_doe123&destination=GA3F2N3N4KVZ255TM74J5J7N3N4KVZ255TM74J5J7N3N4KVZ255TM74J&ref=INV-12345",
    "username": "john_doe123",
    "destination": "GA3F2N3N4KVZ255TM74J5J7N3N4KVZ255TM74J5J7N3N4KVZ255TM74J",
    "referenceId": "INV-12345",
    "metadata": {
      "normalized": false,
      "assetType": "credit_alphanum4",
      "assetIssuer": "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN",
      "linkType": "private",
      "securityLevel": "high",
      "isExpiring": true,
      "expiresInDays": 30
    }
  }
}
```

## Validation Rules Summary

### Amount
- Range: 0.0000001 to 1,000,000 XLM
- Normalized to 7 decimal places

### Memo
- Max length: 28 characters after sanitization
- Sanitized to remove `<>"'` characters

### Asset
- Must be in whitelist: XLM, USDC, AQUA, yXLM
- Normalized to canonical format

### Username
- 1-32 lowercase alphanumeric characters
- May include hyphens and underscores
- Cannot start or end with special characters
- Reserved words blocked

### Destination
- Valid Stellar public key format
- 56 characters: G + 55 base32 characters

### Reference ID
- 1-64 alphanumeric characters, hyphens, or underscores

### Expiration Days
- Range: 1-365 days

## Frontend Integration

The enhanced metadata provides frontend applications with:
1. **Predictable data structure** - Consistent field types and formats
2. **Security indicators** - Help users understand link security level
3. **Asset information** - Type and issuer details for better UX
4. **Link classification** - Different handling for username/private/standard links
5. **Expiration awareness** - Clear indication of link validity period

## Migration Guide

### For Existing Clients
- Existing requests will continue to work unchanged
- New optional fields can be added gradually
- Response structure is backward compatible

### For New Implementations
- Utilize the new validation fields for better user experience
- Leverage the enhanced metadata for richer UI components
- Implement security level indicators in your interface