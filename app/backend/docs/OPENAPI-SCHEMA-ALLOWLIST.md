# OpenAPI Schema Allowlist Documentation

This document explains the intentional exclusions from OpenAPI schema generation and validation gate checks in the QuickEx backend API.

## Background

To guarantee high API documentation quality and prevent silent API regressions for integrating clients, QuickEx runs a CI gate (`pnpm run openapi:check`) that validates:
1. Every registered route exposes an explicit response schema definition (via `@ApiResponse`, `@ApiOkResponse`, `@ApiCreatedResponse`, etc.).
2. Every declared DTO field contains a valid OpenAPI type definition (either via explicit `@ApiProperty`, primitive types, or `$ref` links).

When an endpoint or schema cannot or should not expose a standard JSON response model (such as binary streams, external scrape endpoints, or internal demo harnesses), it must be recorded in this allowlist with a documented rationale.

## Configured Route Allowlist

The machine-readable allowlist is stored in [`app/backend/docs/openapi-schema-allowlist.json`](./openapi-schema-allowlist.json).

### 1. `/health` (GET)
- **Category:** Infrastructure / Liveness Probe
- **Rationale:** Returns a lightweight shallow ping (`{ status: "ok" }`) consumed by load balancers, container orchestrators, and uptime monitors.

### 2. `/metrics` (GET)
- **Category:** Observability / Metrics Scraper
- **Rationale:** Exposes Prometheus exposition format (`text/plain; version=0.0.4; charset=utf-8`) for scraping by Prometheus or OpenTelemetry collectors. Does not return JSON.

### 3. `/admin/audit/export` (GET)
- **Category:** Administrative Export / Streaming Download
- **Rationale:** Streams an exported `text/csv` audit log file attachment directly to the client rather than a structured JSON payload.

### 4. `/seed-reset/status` & `/seed-reset/reset` (GET/POST) (including `/api/seed-reset/*` aliases)
- **Category:** Internal / Sandbox Demo Only
- **Rationale:** Internal testbed harness used exclusively to reset and re-seed fixture data in sandbox and preview environments. Not intended for public API client generation.

---

## Modifying the Allowlist

Any additions to the allowlist must:
1. Include an explicit entry in `openapi-schema-allowlist.json` with the exact path, HTTP method, and justification `reason`.
2. Be documented in this file with context on why standard schema annotation is not suitable.
3. Be reviewed by API maintainers during pull request CI validation.
