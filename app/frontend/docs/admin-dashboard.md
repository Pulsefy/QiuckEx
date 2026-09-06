# Admin Dashboard — Testnet Health

This page collects the screenshots and notes for the Testnet Health admin dashboard.

- Testnet Health overview: [public/screenshots/admin/testnet-health-placeholder.svg](../public/screenshots/admin/testnet-health-placeholder.svg)
- Registry panel: [public/screenshots/admin/registry-placeholder.svg](../public/screenshots/admin/registry-placeholder.svg)
- Indexer lag panel: [public/screenshots/admin/indexer-placeholder.svg](../public/screenshots/admin/indexer-placeholder.svg)
- Smoke tests panel: [public/screenshots/admin/smoke-placeholder.svg](../public/screenshots/admin/smoke-placeholder.svg)

Access the admin console at `/admin` (requires admin auth in production). The Testnet Health panel surfaces:

- Contract registry version & quick link to registry entries
- Indexer lag (seconds) & link to transactions
- Smoke test run statuses with severity: `Blocker` / `Warning` / `OK`
- Links to transaction lists, webhook logs, and registry entries for drilldown

Severity states are visually indicated using border and background colors, and filters allow focusing on blockers or warnings.
