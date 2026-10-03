# Cross-App Testing Strategy Guide

> **Related Documents**: 
> - For CI/CD workflow configurations and automated pipeline triggers, see [.github/workflows/](../.github/workflows/).
> - For smart contract specific test execution, see `app/contract/README.md`.

---

## 1. Backend Testing Layers

The QuickEx backend is equipped with five distinct Jest configurations alongside dedicated smoke specs to target different levels of code verification. Contributors should choose the appropriate layer depending on the scope of their changes:

| Test Layer | Configuration File | Purpose & Scope | When to Add/Run |
| :--- | :--- | :--- | :--- |
| **Unit** | `jest.unit.config.ts` | Fast, isolated tests for pure functions, domain logic, and individual services with all external dependencies mocked. | When writing new utility functions, domain rules, or isolated service methods. |
| **Integration** | `jest.int.config.ts` | Verifies interactions between multiple backend services, database repositories, and Redis/cache clients. | When adding new database queries, caching layers, or multi-service workflows. |
| **End-to-End (E2E)** | `jest.e2e.config.ts` | Validates complete HTTP request-response cycles, middleware execution, guards, and controllers. | When exposing new REST endpoints, authentication guards, or interceptors. |
| **Fuzz** | `jest.fuzz.config.ts` | Tests backend resilience against high-volume, randomized, or malformed input payloads. | When hardening critical financial transaction or security-sensitive parsing logic. |
| **Smoke Specs** | Configured inline | Sanity checks verifying critical service initialization and basic health endpoints. | As a quick post-deployment or pre-commit sanity check. |

---

## 2. Soroban Smart Contract Fuzzing & Snapshots

Smart contract logic under `app/contract/` undergoes rigorous testing via Rust-based test suites:

* **Fuzz Test Harness (`contracts/quickex/src/fuzz_test.rs`)**: Executes randomized property-based inputs against Soroban contract entrypoints to uncover potential integer overflows, unhandled edge cases, or state corruption vulnerabilities.
* **Snapshot Directory**: Maintains historical state outputs, gas consumption benchmarks, and execution baselines. When modifying core token swap or vault logic, run cargo tests with snapshot updates (`cargo test -- --test-threads=1`) to review state diffs.

---

## 3. Frontend & Mobile Test Scripts & CI Reality

### ⚠️ Important Note on Frontend & Mobile Test Scripts
The `test` scripts in `app/frontend/package.json` and `app/mobile/package.json` currently echo a placeholder message (`'Skipping frontend/mobile checks in backend release pipeline'`). 

* **What Contributors Should Run Instead**: 
  * For Frontend: Run `pnpm --filter frontend test` or `npm run test --workspace=frontend` locally to execute Vitest/Jest suites.
  * For Mobile: Run `pnpm --filter mobile test` or execute Expo testing commands locally before submitting changes.

### 4. CI Workflow Integration
To see what automated verification runs on your pull request, inspect the workflow definitions under `.github/workflows/`:
* Backend test matrices run unit, integration, and E2E suites on every push.
* Smart contract fuzz suites and cargo test checks run in parallel job runners.

---

### Implementation Metadata & Commit

```text
docs(testing): add comprehensive cross-app testing strategy guide (#1138)

- Document the five backend Jest configurations (unit, int, e2e, fuzz, smoke) and when to use each
- Detail Soroban contract fuzz test harnesses and snapshot directory workflows
- Clarify frontend/mobile no-op test script placeholders and provide local execution commands
- Cross-link CI workflows under .github/workflows/