# QuickEx Contract Events Schema

This document defines the indexer-facing contract event schema for `quickex`.

## Design goals

- Stable topic names for long-lived integrations.
- Minimal but expressive payload fields.
- Consistent payload shape and topic ordering.
- Clear domain separation: `Escrow*`, `Admin*`, `Privacy*`.

## Naming convention

- Event names use `PascalCase` topics.
- Event structs use `<Topic>NameEvent` in code.
- All events include `timestamp` in data payload.

## Topic and payload rules

1. **Escrow lifecycle events**
   - Topic[0] = event name
   - Topic[1] = `commitment`
   - Topic[2] = `owner`
   - Data = domain-specific fields (`token`, `amount`, optional `expires_at`, `timestamp`)

2. **Admin action events**
   - Topic[0] = event name
   - Topics include admin identity fields relevant to the action
   - Data contains only action state plus `timestamp`

3. **Privacy events**
   - Topic[0] = event name
   - Topic[1] = account/owner
   - Data = state change + `timestamp`

## Current event catalogue

### Privacy

- `PrivacyToggled`
  - Topics: `owner`
  - Data: `enabled`, `timestamp`

### Escrow

- `EscrowDeposited`
  - Topics: `commitment`, `owner`
  - Data: `token`, `amount`, `expires_at`, `timestamp`

- `EscrowWithdrawn`
  - Topics: `commitment`, `owner`
  - Data: `token`, `amount`, `timestamp`

- `EscrowRefunded`
  - Topics: `commitment`, `owner`
  - Data: `token`, `amount`, `timestamp`

### Admin

- `ContractPaused`
  - Topics: `admin`
  - Data: `paused`, `timestamp`

- `AdminChanged`
  - Topics: `old_admin`, `new_admin`
  - Data: `timestamp`

- `ContractUpgraded`
  - Topics: `new_wasm_hash`, `admin`
  - Data: `timestamp`
