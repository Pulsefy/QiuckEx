# Testnet Health Console screenshots (FE-46)

Reference assets for the Admin Testnet Health Console (`/admin` → "Testnet Health Console" panel). The console aggregates the `GET /admin/rc-validation/report` and `GET /contracts/registry/deployments` endpoints into one release-readiness view.

## Panels

- Full console overview (blockers table + all four section cards): `/screenshots/testnet-health/console-overview.png`
- Severity filters — blockers-only view via the severity chips: `/screenshots/testnet-health/severity-filter-blockers.png`
- Contract Registry panel with deployment entries linking to explorer + webhook logs: `/screenshots/testnet-health/registry-status.png`
- Indexer Lag panel with lag-vs-threshold indicator: `/screenshots/testnet-health/indexer-lag.png`
- Smoke Runs panel with per-dependency probe status: `/screenshots/testnet-health/smoke-runs.png`
- Environment Metadata panel with network/environment context and parity checks: `/screenshots/testnet-health/environment-metadata.png`

## Severity states

Blockers are classified by the backend as `critical`, `warning`, or `info`. The console:

- shows a summary chip per severity that doubles as a filter,
- dims panels that do not match the selected severity,
- sorts the blockers table critical-first, with remediation hints and an in-page link to the originating panel.

Cross-page links: registry contract IDs open on Stellar Expert, lag/smoke panels link to recent transactions (`/dashboard`), and the registry panel links to webhook delivery logs (`/webhooks`).

Screenshots captured from the running console against representative fixture data.
