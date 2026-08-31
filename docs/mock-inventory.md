# Mock Inventory

## Overview

This document inventories all mock data, placeholder values, hardcoded demo data, and TODO comments in production code paths across the QuickEx codebase. Its purpose is to help contributors clearly distinguish **intentional scaffolding** (mocks used deliberately for UI development, demos, preview environments, or graceful fallback) from **unintended technical debt** (incomplete production logic, stubs that mask missing backend integrations, and TODOs for deferred implementation work).

All inventory entries are tracked with precise file paths, line numbers, code snippets, classifications, and (for technical debt) required Wave 8 removal actions.

## Exclusions

This inventory **explicitly excludes** the following, which are managed under existing test infrastructure and are not considered production code path mocks:

- Test files: `*.test.*`, `*.spec.*`
- Test fixtures and test-only utilities
- `__tests__/` directories (at any depth)
- `__mocks__/` Jest mock directories
- Backend `test/` integration/E2E directories
- Documentation files (`.md`) unless they reference production code behavior

---

## Inventory

### Frontend

---

#### frontend/src/lib/mockData.ts

- **Line:** 12
- **Snippet:** `export const MOCK_USERS: User[] = [`
- **Description:** Array of 8 mock user profiles (Alex, Sarah, Jordan, Taylor, Vitalik, Satoshi, Alice, Bob) with fake follower counts, bio text, and avatar colors used to populate the discovery page and global profile search components.
- **Classification:** intentional scaffolding
- **Action:** N/A — used for preview/UI development until live discovery API ships

---

#### frontend/src/hooks/marketplaceApi.ts

- **Line:** 41
- **Snippet:** `const MOCK_LISTINGS: MarketplaceListing[] = [`
- **Description:** 8 hardcoded marketplace username listings (pay, sol, nova, satoshi, alex, defi, lux, web3) with fake bid amounts, bid counts, watcher counts, and verification flags.
- **Classification:** intentional scaffolding
- **Action:** N/A — fallback data source when backend marketplace endpoint fails (see catch block at line 257)

---

#### frontend/src/hooks/marketplaceApi.ts

- **Line:** 156
- **Snippet:** `const MOCK_USER_BIDS: UserBid[] = [`
- **Description:** 2 mock user bid records (nova @ 1200 losing bid, lux @ 620 winning bid) returned by `fetchUserBids()` with an artificial 700ms setTimeout delay to simulate network latency.
- **Classification:** unintended technical debt
- **Action:** To be removed in Wave 8 (create/link issue)

---

#### frontend/src/hooks/marketplaceApi.ts

- **Line:** 173
- **Snippet:** `const MOCK_USER_LISTINGS: UserListing[] = [`
- **Description:** Single mock user listing (stellardev with 300 min bid) returned by `fetchUserListings()` with an artificial 700ms setTimeout delay simulating backend latency.
- **Classification:** unintended technical debt
- **Action:** To be removed in Wave 8 (create/link issue)

---

#### frontend/src/hooks/marketplaceApi.ts

- **Line:** 257–259
- **Snippet:** `cachedListings = MOCK_LISTINGS; return MOCK_LISTINGS;`
- **Description:** Catch-block fallback in `fetchListings()` that silently substitutes the MOCK_LISTINGS array when the live `/marketplace` backend endpoint returns an error or is unreachable.
- **Classification:** intentional scaffolding
- **Action:** N/A — graceful degradation for preview/offline environments; keep but audit in Wave 8 whether silent fallback without user notice is acceptable for production

---

#### frontend/src/hooks/marketplaceApi.ts

- **Line:** 407–422
- **Snippet:** `placeBid() { setTimeout(() => { if (Math.random() < 0.1) { resolve({ success: false...`
- **Description:** Simulated bid placement that resolves after 2200ms with a ~10% random chance of simulated wallet rejection; never actually calls a smart contract or backend.
- **Classification:** unintended technical debt
- **Action:** To be removed in Wave 8 (create/link issue)

---

#### frontend/src/hooks/marketplaceApi.ts

- **Line:** 195–198
- **Snippet:** `let category... if (["satoshi", "btc", ...].includes(lower)) category = "crypto";`
- **Description:** Hardcoded keyword-to-category mapping in `mapBackendListingToCardListing()` that assigns listing categories (trending/short/og/crypto/brand) based on username string matching rather than backend data.
- **Classification:** unintended technical debt
- **Action:** To be removed in Wave 8 (create/link issue)

---

#### frontend/src/hooks/mockApi.ts

- **Line:** 1
- **Snippet:** `export async function mockFetch<T>(response: T, delay = 1200)`
- **Description:** Generic mock fetch helper that wraps any value in a delayed Promise (default 1200ms) to simulate network latency. Used by the dashboard page for activity items loading.
- **Classification:** intentional scaffolding
- **Action:** N/A — reusable UI development helper; callsites should migrate to real APIs

---

#### frontend/src/hooks/mockApi.ts

- **Line:** 7
- **Snippet:** `export async function mockContractCall(action: "extend" | "cleanup", id: string)`
- **Description:** Mock Soroban contract interaction that logs a message and resolves `true` after 800ms instead of actually invoking the escrow contract for TTL extension or storage cleanup.
- **Classification:** unintended technical debt
- **Action:** To be removed in Wave 8 (create/link issue)

---

#### frontend/src/hooks/useRealtimeUpdates.ts

- **Line:** 21–22
- **Snippet:** `// Mock WebSocket simulation for real-time bid updates; class MockWebSocket {`
- **Description:** Entire in-memory simulated WebSocket class (`MockWebSocket`) that periodically (every 5s with 30% chance) emits synthetic BidUpdate events with random USDC bid increases, random bidder addresses, and random usernames.
- **Classification:** intentional scaffolding
- **Action:** N/A — used to develop real-time UI interactions before live WebSocket endpoint is available

---

#### frontend/src/app/dashboard/page.tsx

- **Line:** 34
- **Snippet:** `const ACTIVITY_ITEMS: ActivityItem[] = [`
- **Description:** 3 hardcoded dashboard activity items with fake transaction IDs (GD2P…5H2W etc.), memo text, timestamps, and status values. Fed to `mockFetch()` and rendered as the dashboard activity feed.
- **Classification:** unintended technical debt
- **Action:** To be removed in Wave 8 (create/link issue)

---

#### frontend/src/app/dashboard/page.tsx

- **Line:** 214
- **Snippet:** `await mockContractCall("extend", id);`
- **Description:** Dashboard "Extend TTL" action handler that invokes `mockContractCall` instead of dispatching a real Soroban transaction to bump storage TTL.
- **Classification:** unintended technical debt
- **Action:** To be removed in Wave 8 (create/link issue)

---

#### frontend/src/app/dashboard/page.tsx

- **Line:** 219
- **Snippet:** `await mockContractCall("cleanup", id);`
- **Description:** Dashboard "Reclaim Storage Deposit" (cleanup) action handler that invokes `mockContractCall` instead of invoking the real contract cleanup operation.
- **Classification:** unintended technical debt
- **Action:** To be removed in Wave 8 (create/link issue)

---

#### frontend/src/app/settings/page.tsx

- **Line:** 27
- **Snippet:** `// TODO: Call API to save profile`
- **Description:** The `handleSave` function for user profile editing only logs to console and has a TODO noting the absence of any actual PUT/PATCH API call to persist profile changes (avatar, bio, social handles, display name).
- **Classification:** unintended technical debt
- **Action:** To be removed in Wave 8 (create/link issue)

---

#### frontend/src/app/settings/teams/page.tsx

- **Line:** 14
- **Snippet:** `const initialMembers: TeamMember[] = [ { id: "1", name: "John Doe", ...`
- **Description:** Three hardcoded team member objects (John Doe admin, Sarah Smith operator, Mike Wilson viewer pending) used as the initial state for the Teams management settings page.
- **Classification:** unintended technical debt
- **Action:** To be removed in Wave 8 (create/link issue)

---

#### frontend/src/app/settings/teams/page.tsx

- **Line:** 22
- **Snippet:** `const [userRole] = useState<...>("admin"); // Mock current user role`
- **Description:** Hardcoded current user role = "admin" with inline comment acknowledging this is a mock. Gating all role-change and remove-member actions to admin-only, but the role itself is never loaded from session/auth.
- **Classification:** unintended technical debt
- **Action:** To be removed in Wave 8 (create/link issue)

---

#### frontend/src/app/admin/layout.tsx

- **Line:** 4–8
- **Snippet:** `// Mock auth check; const checkIsAdmin = () => { const isAdmin = true;`
- **Description:** Admin route protection bypass — `checkIsAdmin()` always returns `true` with a comment acknowledging this is a "Set to true for demo purposes" mock; no actual session, cookie, or role-based admin check is performed.
- **Classification:** unintended technical debt
- **Action:** To be removed in Wave 8 (create/link issue) — severe: this leaves admin console unprotected in any environment where the file ships

---

#### frontend/src/components/payment-states/ActivePaymentState.tsx

- **Line:** 148
- **Snippet:** `const mockXdr = "AAAAA" + Math.random()... + "xdrSignedPayload314159..."`
- **Description:** Payment flow signature step generates a synthetic signed transaction XDR string by concatenating a fixed prefix, random characters, and a hardcoded payload suffix, then reports the transaction as "signed" without actually calling a wallet connector.
- **Classification:** intentional scaffolding
- **Action:** N/A — simulator used for UI/UX demos of the signing flow; gated behind simulator-outcome selector

---

### Mobile

---

#### mobile/src/data/mockReceipt.ts

- **Line:** 3
- **Snippet:** `export const mockReceiptPending: ReceiptData = {`
- **Description:** Full mock pending-state receipt with fake IDs (rec_test_001), hardcoded sender/recipient G… Stellar addresses, synthetic timestamps (2026-06-25), mock contract IDs/wasm hashes, and a 5-step timeline with transaction and support bundle references.
- **Classification:** intentional scaffolding
- **Action:** N/A — used for receipt screen UI development and screenshot testing

---

#### mobile/src/data/mockReceipt.ts

- **Line:** 74
- **Snippet:** `export const mockReceiptSuccess: ReceiptData = { ...mockReceiptPending,`
- **Description:** Success-state receipt variant that spreads mockReceiptPending and overrides the timeline to show all 5 steps completed (validated, executed, settled).
- **Classification:** intentional scaffolding
- **Action:** N/A

---

#### mobile/src/data/mockReceipt.ts

- **Line:** 109
- **Snippet:** `export const mockReceiptFailed: ReceiptData = { ...mockReceiptPending,`
- **Description:** Failed-state receipt variant overriding timeline with "Validation Failed — Insufficient balance" step + auto-refund step, plus synthetic failed txHash.
- **Classification:** intentional scaffolding
- **Action:** N/A

---

#### mobile/src/data/mockReceipt.ts

- **Line:** 136
- **Snippet:** `export const mockReceiptRefund: ReceiptData = { ...mockReceiptPending,`
- **Description:** Refund-state receipt variant showing a completed refund step with a synthetic 0xtxrefund… txHash.
- **Classification:** intentional scaffolding
- **Action:** N/A

---

#### mobile/src/screens/NotificationScreen.tsx

- **Line:** 26
- **Snippet:** `const MOCK_NOTIFICATIONS: Notification[] = [`
- **Description:** Three mock in-app notifications — a USDC payment received from Alice, an XLM payment sent to Bob, and a system welcome message. Used as the initial state for the notifications FlatList and not replaced by any API call.
- **Classification:** unintended technical debt
- **Action:** To be removed in Wave 8 (create/link issue)

---

### Backend

---

#### backend/src/fiat-ramps/fiat-ramps.service.ts

- **Line:** 9–28
- **Snippet:** `// Mock implementation for available anchors; return { data: [{ id: 'moneygram' ...`
- **Description:** `getAvailableAnchors()` returns a static two-element anchor list (MoneyGram + Banxa) with hardcoded domains, supported asset lists, and types. No SEP-1 TOML resolution or directory lookup is performed.
- **Classification:** unintended technical debt
- **Action:** To be removed in Wave 8 (create/link issue)

---

#### backend/src/fiat-ramps/fiat-ramps.service.ts

- **Line:** 31–45
- **Snippet:** `const mockInteractiveUrl = 'https://${anchorDomain}/sep24/interactive?...'`
- **Description:** `initiateDeposit()` constructs a mock SEP-24 interactive URL by template interpolation instead of performing the required SEP-10 authentication handshake and calling the anchor's TRANSFER_SERVER_SEP0024 endpoint per Stellar standards. The comment at line 34–35 explicitly calls out the missing real integration.
- **Classification:** unintended technical debt
- **Action:** To be removed in Wave 8 (create/link issue)

---

#### backend/src/fiat-ramps/fiat-ramps.service.ts

- **Line:** 51–65
- **Snippet:** `const mockInteractiveUrl = 'https://${withdrawalDto.anchorDomain}/sep24/interactive?...'`
- **Description:** `initiateWithdrawal()` has the same stub behavior as deposit — generates a synthetic interactive URL string and returns a fake `transaction_id` prefixed with `wth_` + `Date.now()`, never touching a real anchor SEP-24 server.
- **Classification:** unintended technical debt
- **Action:** To be removed in Wave 8 (create/link issue)

---

#### backend/src/receipts/receipts.service.ts

- **Line:** 206–214
- **Snippet:** `// TODO: replace with actual Supabase/database call; return { submittedAt: new Date().toISOString() }`
- **Description:** `fetchIndexerMetadata()` method — invoked on every receipt lookup — does not query the indexer/database. Instead it always returns a fresh object with the current `Date().toISOString()` as `submittedAt` and a network value read from config. The TODO comment explicitly requests replacement with a real Supabase call.
- **Classification:** unintended technical debt
- **Action:** To be removed in Wave 8 (create/link issue)

---

#### backend/src/receipts/receipts.service.ts

- **Line:** 188–190
- **Snippet:** `cpuInstructions: rpcResult.resultMetaXdr ? undefined  // Would decode XDR here in production : undefined,`
- **Description:** `fetchSorobanResult()` always sets `cpuInstructions` to `undefined` regardless of whether XDR is present, with a comment acknowledging that production would decode the resultMetaXdr. CPU instructions are not extracted from the RPC response.
- **Classification:** unintended technical debt
- **Action:** To be removed in Wave 8 (create/link issue)

---

#### backend/src/links/recurring-payments.scheduler.ts

- **Line:** 226
- **Snippet:** `// TODO: Integrate with usernames module to resolve username to Stellar address`
- **Description:** `resolveUsernameToAddress()` private helper unconditionally logs a warning and returns `null`. It never queries the usernames table/module, meaning any recurring payments created against a username (instead of a raw G… address) will silently fail to dispatch.
- **Classification:** unintended technical debt
- **Action:** To be removed in Wave 8 (create/link issue)

---

#### backend/src/job-queue/handlers/export-generation.handler.ts

- **Line:** 252
- **Snippet:** `// TODO: Implement webhook delivery`
- **Description:** Webhook delivery branch in `deliverExport()` logs an "not yet implemented" message and returns without making any outbound HTTP call, queuing a webhook request, or persisting delivery state. Users who request webhook export delivery silently get nothing.
- **Classification:** unintended technical debt
- **Action:** To be removed in Wave 8 (create/link issue)

---

#### backend/src/job-queue/handlers/export-generation.handler.ts

- **Line:** 258
- **Snippet:** `// TODO: Implement email delivery`
- **Description:** Email delivery branch similarly logs and returns — no Mailgun/Sendgrid/SMTP integration, no MIME construction, no email actually sent to the user.
- **Classification:** unintended technical debt
- **Action:** To be removed in Wave 8 (create/link issue)

---

#### backend/src/job-queue/handlers/export-generation.handler.ts

- **Line:** 264
- **Snippet:** `// TODO: Implement download link generation (store in S3/Supabase Storage)`
- **Description:** Download delivery branch does not upload any export artifact to object storage; it just logs. Users clicking "download" exports never get a retrievable file.
- **Classification:** unintended technical debt
- **Action:** To be removed in Wave 8 (create/link issue)

---

#### backend/src/job-queue/handlers/export-generation.handler.ts

- **Line:** 335
- **Snippet:** `// TODO: Notify user of export failure via notification system`
- **Description:** `onPermanentFailure()` handler logs the failure server-side but does not emit a notification event, in-app notification, email, or any user-visible signal. Export failures are invisible to the requesting user.
- **Classification:** unintended technical debt
- **Action:** To be removed in Wave 8 (create/link issue)

---

#### backend/src/demos/demo.fixtures.ts

- **Line:** 31
- **Snippet:** `export const DEMO_ADDRESSES = { ALICE: 'GDEMOALICE000000000000000000000000000000000000000000000001', ...`
- **Description:** Four deterministic demo-only Stellar addresses (ALICE, BOB, MERCHANT, ESCROW) with recognizable GDEMO prefixes, plus a testnet USDC issuer constant. Scoped to the admin-only demo seed/clear endpoints and annotated as "testnet-only, no real funds."
- **Classification:** intentional scaffolding
- **Action:** N/A — gated behind admin-scoped demo API endpoints and explicitly restricted to testnet

---

#### backend/src/demos/demo.fixtures.ts

- **Line:** 44
- **Snippet:** `export const DEMO_LINKS: readonly DemoLink[] = [`
- **Description:** Four demo payment links (demo-xlm-tip, demo-usdc-payment, demo-merchant-checkout, demo-expired-link) with fixed IDs, slugs, amounts, and demo address recipients.
- **Classification:** intentional scaffolding
- **Action:** N/A — managed by DemoService seed/clear lifecycle; IDs are prefixed `demo_link_` to avoid collisions

---

#### backend/src/demos/demo.fixtures.ts

- **Line:** 101 (inferred from array start)
- **Snippet:** `export const DEMO_TRANSACTIONS: readonly DemoTransaction[] = [`
- **Description:** Four demo transactions (ids demo_tx_001 through demo_tx_004) linking to the DEMO_LINKS fixtures with synthetic stellarTxHash values and fixed amounts.
- **Classification:** intentional scaffolding
- **Action:** N/A

---

## Maintenance

This inventory must stay synchronized with the production code at all times. When modifying code in `app/frontend/`, `app/mobile/`, or `app/backend/`, contributors are responsible for the following bookkeeping:

1. **New mocks must be added.** Whenever a new mock data array, stubbed service method, synthetic fallback, or TODO-for-incomplete-logic is introduced to a production code path, add a new entry to the relevant section of this file within the same PR. Include the exact line number from the PR diff.

2. **Removed mocks must be deleted.** When you replace a mock with real integration (live API calls, real contract invocation, real WebSocket, etc.), **delete** the corresponding inventory entry from this file. Do not leave stale "historical" entries.

3. **Classification must be honest.** If you are unsure whether a stub is "intentional scaffolding" vs "technical debt," ask: *Would a production mainnet deployment be broken or degraded if this mock shipped unchanged?* If yes → "unintended technical debt." If it's a deliberate demo/preview fallback with a safe user-facing failure mode → "intentional scaffolding." When in doubt, classify as technical debt and add a Wave 8 action.

4. **Line numbers must stay accurate.** After any refactor that shifts line numbers in an inventoried file, run a quick pass through the file section to correct any shifted line references. Stale line numbers defeat the purpose of the inventory.

5. **Periodic re-scan.** At the start of each wave, run the scan pattern used to produce this inventory (TODO/FIXME/HACK + MOCK_/mock/Mock + hardcoded/demo/placeholder keywords, excluding test paths) and reconcile the results against this document to catch any entries that slipped through the manual process.
