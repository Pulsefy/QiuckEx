# Architecture Overview

## Backend & Contract Interactions

```mermaid
graph TD
  FE[Frontend] -- REST/gRPC --> BE[Backend]
  BE -- Soroban SDK --> SC[Smart Contract]
  SC -- Events --> BE
  BE -- Webhooks --> FE
```

- **Frontend** communicates with the **Backend** via REST/gRPC APIs.
- **Backend** interacts with **Soroban Smart Contracts** for payment logic.
- **Smart Contracts** emit events consumed by the Backend.
- **Backend** notifies the Frontend via webhooks or polling.

## Key Components
- **Frontend:** Next.js app for user interaction
- **Backend:** NestJS API server
- **Contracts:** Soroban smart contracts (Rust)

## API Routing

The backend registers no global route prefix: a controller's `@Controller(...)`
argument is its full public path. Canonical prefixes are unprefixed resource
paths, and the rule is enforced by a check that runs over every
`*.controller.ts`. See [Routing Conventions](./ROUTING-CONVENTIONS.md).

---

For more details, see [docs/](./).
