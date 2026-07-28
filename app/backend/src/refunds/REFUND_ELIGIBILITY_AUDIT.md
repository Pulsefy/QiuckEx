# Refund Eligibility Audit Endpoint

## Overview

The refund eligibility audit endpoint provides support and admin users with detailed information about why a refund is or is not allowed for a given entity (payment, escrow, or link) **before attempting the refund**. This helps support staff understand refund decisions and communicate them to users.

## Endpoint

```
POST /admin/refunds/check-eligibility
```

### Authentication

Requires API key with `refunds:write` scope.

### Request Body

```json
{
  "entityType": "payment" | "escrow" | "link",
  "entityId": "string"
}
```

### Response

```json
{
  "eligible": boolean,
  "reasonCode": "ELIGIBLE" | "INVALID_STATE" | "ENTITY_NOT_FOUND" | "ALREADY_REFUNDED" | "TOO_OLD" | "CONTRACT_NOT_READY" | "INDEXER_NOT_SYNCED",
  "message": "Human-readable explanation",
  "details": {
    "currentState": "string (optional)",
    "ageInDays": number (optional),
    "maxAgeInDays": number (optional),
    "existingRefundId": "string (optional)"
  }
}
```

## Reason Codes

### ELIGIBLE
- **Meaning**: The entity is eligible for refund
- **Next Steps**: Proceed with refund initiation
- **Example**: Recent payment in `paid` state

### INVALID_STATE
- **Meaning**: The entity is in a state that cannot be refunded
- **Details**: `details.currentState` shows the current state
- **Next Steps**: Explain to user why refund cannot be processed
- **Examples**:
  - Payment in `pending` or `failed` state (must be `paid`)
  - Escrow in `pending` or `expired` state (must be `active` or `claimed`)
  - Link in `draft` or `active` state (must be `PAID`)

### ENTITY_NOT_FOUND
- **Meaning**: The entity does not exist in the database
- **Next Steps**: Verify the entity ID with the user
- **Example**: Typo in payment ID or deleted record

### ALREADY_REFUNDED
- **Meaning**: A refund has already been initiated or approved for this entity
- **Details**: `details.existingRefundId` shows the refund attempt ID
- **Next Steps**: Check the status of the existing refund
- **Example**: Duplicate refund request

### TOO_OLD
- **Meaning**: The entity is beyond the refund window (default: 90 days)
- **Details**: `details.ageInDays` and `details.maxAgeInDays` show the age limits
- **Next Steps**: Escalate to senior support for manual review
- **Example**: Payment from 120 days ago

### CONTRACT_NOT_READY
- **Meaning**: Smart contract prerequisites are not met (future use)
- **Next Steps**: Wait for contract readiness or escalate
- **Example**: Contract deployment pending

### INDEXER_NOT_SYNCED
- **Meaning**: Blockchain indexer has not caught up (future use)
- **Next Steps**: Wait for indexer sync or check manually
- **Example**: Recent transaction not yet indexed

## State Checks

### Payment Eligibility
- **Required State**: `paid`
- **Rejected States**: `pending`, `processing`, `failed`
- **Age Limit**: 90 days from creation

### Escrow Eligibility
- **Required States**: `active` or `claimed`
- **Rejected States**: `pending`, `expired`, `cancelled`
- **Age Limit**: 90 days from creation

### Link Eligibility
- **Required State**: `PAID`
- **Rejected States**: `DRAFT`, `ACTIVE`, `EXPIRED`, `REFUNDED`
- **Age Limit**: 90 days from creation

## Usage Examples

### Example 1: Eligible Payment

**Request:**
```bash
curl -X POST https://api.quickex.com/admin/refunds/check-eligibility \
  -H "X-API-Key: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "entityType": "payment",
    "entityId": "pay_abc123"
  }'
```

**Response:**
```json
{
  "eligible": true,
  "reasonCode": "ELIGIBLE",
  "message": "Payment is eligible for refund",
  "details": {
    "currentState": "paid",
    "ageInDays": 15,
    "maxAgeInDays": 90
  }
}
```

### Example 2: Invalid State

**Request:**
```bash
curl -X POST https://api.quickex.com/admin/refunds/check-eligibility \
  -H "X-API-Key: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "entityType": "payment",
    "entityId": "pay_xyz789"
  }'
```

**Response:**
```json
{
  "eligible": false,
  "reasonCode": "INVALID_STATE",
  "message": "Payment is in pending state, must be paid",
  "details": {
    "currentState": "pending"
  }
}
```

### Example 3: Too Old

**Request:**
```bash
curl -X POST https://api.quickex.com/admin/refunds/check-eligibility \
  -H "X-API-Key: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "entityType": "escrow",
    "entityId": "esc_old456"
  }'
```

**Response:**
```json
{
  "eligible": false,
  "reasonCode": "TOO_OLD",
  "message": "Escrow is too old for refund (120 days old, max 90 days)",
  "details": {
    "ageInDays": 120,
    "maxAgeInDays": 90
  }
}
```

### Example 4: Already Refunded

**Request:**
```bash
curl -X POST https://api.quickex.com/admin/refunds/check-eligibility \
  -H "X-API-Key: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "entityType": "link",
    "entityId": "link_duplicate"
  }'
```

**Response:**
```json
{
  "eligible": false,
  "reasonCode": "ALREADY_REFUNDED",
  "message": "A pending refund already exists for this entity",
  "details": {
    "existingRefundId": "ref_123abc"
  }
}
```

## Security and Privacy

### No Sensitive Data Exposure
The endpoint does not expose:
- Internal implementation details (database schema, indexer specifics)
- Secret keys or credentials
- Raw transaction details
- User PII beyond what's necessary for support

### Redacted Information
All responses contain only:
- Public state information
- Calculated age (not exact timestamps)
- Reason codes (stable identifiers)
- Support-useful context

## Testing

See test files:
- `refunds.eligibility.spec.ts` - Unit tests for eligibility logic
- `refunds.service.spec.ts` - Integration tests for service methods

Test coverage includes:
- ✅ Positive scenarios (eligible entities)
- ✅ Negative scenarios (invalid state, too old, not found)
- ✅ Boundary conditions (exactly at age limit)
- ✅ Reason code stability (consistent codes for same conditions)
- ✅ Edge cases (existing refunds, all entity types)

## Future Enhancements

The following reason codes are reserved for future use:
- `CONTRACT_NOT_READY`: Smart contract state validation
- `INDEXER_NOT_SYNCED`: Blockchain indexer lag detection

These can be implemented when blockchain integration is complete without changing the API contract.
