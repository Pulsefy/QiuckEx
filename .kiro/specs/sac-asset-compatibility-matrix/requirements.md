# Requirements Document

## Introduction

The SAC (Stellar Asset Contract) Asset Compatibility Matrix feature validates and documents contract behavior across XLM (the native Stellar asset) and common SAC tokens (USDC, AQUA, yXLM). It ensures that transfer semantics, decimal handling, amount normalization, and fee routing work consistently and correctly across all supported asset types. The feature also establishes clear rejection behavior for unsupported assets and invalid issuers, providing deterministic and testable guarantees for the QuickEx platform.

## Glossary

- **SAC**: Stellar Asset Contract — a Soroban smart contract that wraps a classic Stellar asset (native or issued) to expose a standard token interface.
- **XLM**: The native asset of the Stellar network, with no issuer and 7 decimal places of precision.
- **SAC_Token**: An issued Stellar asset (e.g., USDC, AQUA, yXLM) wrapped by a SAC contract, identified by both a code and an issuer public key.
- **Asset_Validator**: The component responsible for normalizing and validating asset inputs against the supported asset registry.
- **Amount_Normalizer**: The component responsible for converting raw numeric amounts to the canonical 7-decimal-place string representation used across the platform.
- **Fee_Router**: The component responsible for computing and routing transaction fees consistently regardless of the asset type being transferred.
- **Supported_Asset_Registry**: The authoritative list of supported assets defined in `SUPPORTED_ASSETS` and `VERIFIED_STELLAR_ASSETS`.
- **Canonical_Amount**: A string representation of an amount formatted to exactly 7 decimal places (e.g., `"10.0000000"`).
- **Issuer**: The Stellar public key of the account that issued a non-native asset.
- **Transfer_Semantics**: The rules governing how an asset moves from sender to recipient, including amount precision, asset identification, and memo handling.

---

## Requirements

### Requirement 1: Asset Identification and Normalization

**User Story:** As a developer integrating with QuickEx, I want asset inputs to be normalized to a canonical form, so that XLM and SAC tokens are identified consistently regardless of how they are provided.

#### Acceptance Criteria

1. WHEN an asset input with code `"xlm"` (any casing) is provided, THE Asset_Validator SHALL normalize it to `{ type: "native", code: "XLM" }` with no issuer field.
2. WHEN an asset input with code `"XLM"` and `type: "native"` is provided, THE Asset_Validator SHALL normalize it to `{ type: "native", code: "XLM" }` with no issuer field.
3. WHEN an asset input with a code of 1–4 characters (excluding XLM) is provided, THE Asset_Validator SHALL normalize it to `{ type: "credit_alphanum4", code: <UPPERCASED_CODE>, issuer: <issuer_if_present> }` — normalization to `credit_alphanum4` SHALL proceed even when the issuer is absent, with issuer validation deferred to the supported-asset check.
4. WHEN an asset input with a code of 5–12 characters and a string issuer value is provided, THE Asset_Validator SHALL normalize it to `{ type: "credit_alphanum12", code: <UPPERCASED_CODE>, issuer: <issuer> }`.
5. THE Asset_Validator SHALL trim leading and trailing whitespace from asset codes before normalization.
6. THE Asset_Validator SHALL produce an identical normalized output when the same valid asset input is normalized more than once (idempotence).
7. WHEN an asset input with an empty or whitespace-only code is provided, THE Asset_Validator SHALL reject it before normalization.
8. WHEN an asset input with a code exceeding 12 characters is provided, THE Asset_Validator SHALL normalize it as `credit_alphanum12` and defer the unsupported-asset check to the registry validation step.

---

### Requirement 2: Supported Asset Validation

**User Story:** As a platform operator, I want only whitelisted assets to be accepted in payment flows, so that unsupported or fraudulent assets are rejected before any processing occurs.

#### Acceptance Criteria

1. WHEN an asset input matching a registered entry in the Supported_Asset_Registry is provided, THE Asset_Validator SHALL return the normalized asset with the code and issuer exactly as stored in the registry, with no additional fields.
2. WHEN an asset input with an unrecognized code is provided, THE Asset_Validator SHALL throw an `UnsupportedAssetError` with a message identifying the rejected asset code.
3. WHEN an asset input for a known code (e.g., `"USDC"`) is provided with an issuer that does not match the registered issuer, THE Asset_Validator SHALL throw an `UnsupportedAssetError`.
4. WHEN an asset input for a non-native asset is provided without an issuer, THE Asset_Validator SHALL throw an `UnsupportedAssetError`.
5. WHEN an asset input with an empty or whitespace-only code is provided, THE Asset_Validator SHALL throw an `UnsupportedAssetError`.
6. Asset code matching in the Supported_Asset_Registry SHALL be case-sensitive after normalization — for example, `"usdc"` normalized to `"USDC"` SHALL match the registry entry `"USDC"`, but a code that remains non-matching after normalization SHALL be rejected.
7. IF an issuer value is provided alongside `code: "XLM"`, THEN THE Asset_Validator SHALL ignore the issuer value and proceed with native asset validation.
8. WHEN XLM is validated, THE Asset_Validator SHALL return `{ type: "native", code: "XLM" }` with no issuer field.

---

### Requirement 3: Decimal Handling and Amount Normalization

**User Story:** As a developer, I want all asset amounts to be normalized to exactly 7 decimal places, so that XLM and SAC token amounts are represented deterministically across the platform.

#### Acceptance Criteria

1. WHEN a numeric amount is provided, THE Amount_Normalizer SHALL format it as a string with exactly 7 decimal places (e.g., `10` → `"10.0000000"`).
2. WHEN a numeric amount with more than 7 decimal places is provided, THE Amount_Normalizer SHALL round it to 7 decimal places using half-up rounding (e.g., `1.00000005` → `"1.0000001"`, `1.00000004` → `"1.0000000"`).
3. WHEN a numeric amount of `0.0000001` (the minimum representable amount) is provided, THE Amount_Normalizer SHALL format it as `"0.0000001"`.
4. WHEN a numeric amount of `1000000` (the maximum allowed amount) is provided, THE Amount_Normalizer SHALL format it as `"1000000.0000000"`.
5. THE Amount_Normalizer SHALL produce identical Canonical_Amount strings for XLM and SAC tokens — no asset-specific decimal offset SHALL be applied.
6. THE Amount_Normalizer SHALL produce the same Canonical_Amount string when the same numeric input is normalized more than once (idempotence).
7. WHEN an amount less than `0.0000001` is provided, THE Amount_Normalizer SHALL reject it with an `AMOUNT_TOO_LOW` error.
8. WHEN an amount greater than `1000000` is provided, THE Amount_Normalizer SHALL reject it with an `AMOUNT_TOO_HIGH` error.
9. IF a non-numeric, negative, or zero amount is provided, THEN THE Amount_Normalizer SHALL reject it with an `INVALID_AMOUNT` error.

---

### Requirement 4: Transfer Semantics Consistency Across Asset Types

**User Story:** As a developer, I want transfer operations to behave identically for XLM and SAC tokens, so that I can build payment flows without asset-specific branching logic.

#### Acceptance Criteria

1. WHEN a payment link is generated for XLM, THE LinksService SHALL produce a canonical URL string containing `asset=XLM` and a 7-decimal-place amount.
2. WHEN a payment link is generated for a SAC_Token (e.g., USDC), THE LinksService SHALL produce a canonical URL string containing the token code and a 7-decimal-place amount, using the same URL format as XLM.
3. WHEN a memo is provided alongside an XLM transfer, THE LinksService SHALL include the sanitized memo in the canonical URL format.
4. WHEN a memo is provided alongside a SAC_Token transfer, THE LinksService SHALL include the sanitized memo in the canonical URL format using the same sanitization rules as XLM.
5. WHEN a payment link is generated for any supported asset, THE LinksService SHALL include `assetType` and `assetIssuer` in the response metadata — `null` for `assetIssuer` when the asset is XLM, and the registered issuer address for SAC tokens. WHERE metadata fields cannot be fully resolved, THE LinksService SHALL include whatever metadata is available rather than failing the request.
6. WHEN `acceptedAssets` includes both XLM and a SAC_Token, THE LinksService SHALL include both in the canonical format and ensure the destination asset is always present in the list.

---

### Requirement 5: Fee Routing Consistency

**User Story:** As a platform operator, I want fee routing to work identically across XLM and SAC token transfers, so that fee calculations are predictable and auditable regardless of asset type.

#### Acceptance Criteria

1. WHEN a transaction fee is computed for an XLM transfer and a SAC_Token transfer with equal input amounts, THE Fee_Router SHALL return equal computed fee values.
2. WHEN asset metadata is retrieved for XLM, THE Asset_Validator SHALL return `decimals: 7`.
3. WHEN asset metadata is retrieved for any asset in the configured supported asset set (USDC, AQUA, yXLM), THE Asset_Validator SHALL return `decimals: 7`.
4. THE Fee_Router SHALL apply the same fee formula to all asset types — no per-asset fee multipliers, offsets, or formula variations SHALL be applied.
5. WHEN a path payment is previewed for a SAC_Token destination and an XLM destination with equal input amounts, THE Fee_Router SHALL return equal fee estimates.
6. IF an asset is encountered whose configured decimal precision is not 7, THEN THE Asset_Validator SHALL reject the operation with a decimal precision mismatch error and SHALL leave the transaction state unchanged.

---

### Requirement 6: Rejection of Unsupported Assets and Invalid Issuers

**User Story:** As a security-conscious operator, I want all unsupported assets and invalid issuers to be rejected with clear, structured errors, so that fraudulent or misconfigured payment links cannot be created.

#### Acceptance Criteria

1. WHEN an asset code not present in the Supported_Asset_Registry is submitted to the link generation endpoint, THE LinksService SHALL return a `400 Bad Request` HTTP response with error code `ASSET_NOT_WHITELISTED`.
2. WHEN a known asset code is submitted with an issuer that does not match the registered issuer, THE LinksService SHALL return a `400 Bad Request` HTTP response with error code `ASSET_NOT_WHITELISTED` and a message containing the rejected asset code and issuer.
3. WHEN any asset other than XLM is submitted without an issuer, THE LinksService SHALL return a `400 Bad Request` HTTP response with error code `ASSET_NOT_WHITELISTED`.
4. WHEN `acceptedAssets` contains one or more unsupported asset codes, THE LinksService SHALL return a `400 Bad Request` HTTP response with error code `ASSET_NOT_WHITELISTED` and SHALL identify the invalid asset codes in the error message.
5. IF an asset code is submitted that differs from a registered asset only in casing (e.g., `"usdc"`), THEN THE Asset_Validator SHALL normalize the code to uppercase before registry lookup. IF the normalized form matches a registered asset with a matching issuer, THEN THE Asset_Validator SHALL accept it. IF the normalized form does not match any registered asset, THEN THE LinksService SHALL return a `400 Bad Request` HTTP response with error code `ASSET_NOT_WHITELISTED`.
6. WHEN an asset with a valid code but a malformed issuer (not a 56-character base32-encoded string beginning with `"G"`) is submitted, THE LinksService SHALL return a `400 Bad Request` HTTP response with error code `ASSET_NOT_WHITELISTED`.

---

### Requirement 7: Asset Compatibility Test Coverage

**User Story:** As a developer, I want comprehensive tests for each critical operation across XLM and SAC tokens, so that regressions in asset-specific behavior are caught automatically.

#### Acceptance Criteria

1. THE Test_Suite SHALL include at least one test for each critical operation (link generation, amount normalization, asset validation, fee routing) using XLM as the asset.
2. THE Test_Suite SHALL include at least one test for each critical operation using USDC (a SAC_Token) as the asset.
3. THE Test_Suite SHALL include negative tests that verify a `400 Bad Request` response with error code `ASSET_NOT_WHITELISTED` is returned for unrecognized asset codes.
4. THE Test_Suite SHALL include negative tests that verify a `400 Bad Request` response with error code `ASSET_NOT_WHITELISTED` is returned for known asset codes with mismatched issuers.
5. THE Test_Suite SHALL include tests that verify the Amount_Normalizer produces identical Canonical_Amount strings for XLM and SAC tokens given the same numeric input.
6. THE Test_Suite SHALL include an idempotency test: for each supported asset, normalizing an amount to Canonical_Amount and normalizing the result again SHALL yield the same Canonical_Amount string.
7. WHEN the Supported_Asset_Registry is extended with a new asset entry, THE Asset_Validator SHALL accept it without requiring changes to validation logic — only the registry entry is needed. THE Asset_Validator SHALL handle any asset type representable by the `SupportedAsset` type union through data-driven registry lookup, not asset-type-specific code branches.
