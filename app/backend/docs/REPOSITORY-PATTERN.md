# Repository Pattern

Services must not talk to Supabase directly. All persistence goes through a
**repository** owned by the domain, exposed as an **interface** and backed by a
**Supabase adapter** registered in the module's dependency-injection container.

This decouples the domain services from the storage engine so that unit tests
run entirely without Supabase (no network, no credentials, no mock query
builder chains).

## Problem

Services were coupled to Supabase in two ways:

1. Injecting the concrete `SupabaseService` and calling its data-access methods
   directly (e.g. `usernames.service.ts`).
2. Reaching through `supabaseService.getClient().from('table')...` from inside a
   service (e.g. `payment-link.service.ts`, `payment-link-expiry.service.ts`,
   `transaction-timeline.service.ts`).

Both make the service hard to test (chainable builder mocks) and impossible to
port to a different persistence layer.

## Pattern

Each domain owns a port/adapter pair:

```
<domain>.repository.ts
├── domain types          (persistence shape, e.g. UsernameRow, ListingPage)
├── interface              (the contract services depend on)
├── DI token               (Symbol, e.g. USERNAMES_REPOSITORY)
└── Supabase adapter       (implements the interface via SupabaseService)
```

- **Services** depend on the interface, injected with `@Inject(TOKEN)`.
- **Modules** bind the token to the adapter with
  `{ provide: TOKEN, useClass: Supabase<Domain>Repository }`.
- **Unit tests** provide an in-memory fake:
  `{ provide: TOKEN, useValue: { ...jest.fn() } }`.

### Conventions

- File name: `<domain>.repository.ts` (e.g. `usernames.repository.ts`).
- Token name: uppercase `<DOMAIN>_REPOSITORY` constant.
- Adapter name: `Supabase<Domain>Repository`.
- Adapter throws domain errors, not storage errors — e.g.
  `SupabaseUsernamesRepository` translates `SupabaseUniqueConstraintError` into
  `UsernameConflictError` so services never import `supabase.errors`.
- Types returned by the interface are domain types, not `supabase-js` row types.

## Repositories in this codebase

| Domain                | File                                                      | Token                         |
| --------------------- | --------------------------------------------------------- | ----------------------------- |
| Usernames             | `src/usernames/usernames.repository.ts`                  | `USERNAMES_REPOSITORY`        |
| Payment links         | `src/links/payment-links.repository.ts`                  | `PAYMENT_LINKS_REPOSITORY`    |
| Transaction timeline  | `src/transaction-timeline/transaction-timeline.repository.ts` | `TRANSACTION_TIMELINE_REPOSITORY` |
| Receipts (indexer)    | `src/receipts/receipt-metadata.repository.ts`            | `RECEIPT_METADATA_REPOSITORY` |

Pre-existing concrete repositories that already follow the same spirit (no
interface token) include `recurring-payments.repository.ts`, `api-keys.repository.ts`,
`crash-reporting.repository.ts`, `dashboard-feed.repository.ts`, and the
`ingestion/*.repository.ts` files. New code should prefer the interface + token
form described here.

## Adding a new repository

1. Create `<domain>.repository.ts` with the interface, DI token, and a
   `Supabase<Domain>Repository` adapter.
2. Update the module: import `SupabaseModule`, add the token provider, and (if
   another module needs the adapter) export the token.
3. Update services to inject the token:
   ```ts
   constructor(
     @Inject(DOMAIN_REPOSITORY)
     private readonly repo: DomainRepository,
   ) {}
   ```
4. Update unit tests to supply an in-memory fake instead of `SupabaseService` /
   `getClient()` chains.

## Testing without Supabase

Unit tests construct the module with a fake repository and never instantiate
`SupabaseService`:

```ts
const repoMock = {
  getPublicKeyByUsername: jest.fn().mockResolvedValue('G...'),
};

const module = await Test.createTestingModule({
  providers: [
    PaymentLinkService,
    { provide: PAYMENT_LINKS_REPOSITORY, useValue: repoMock },
    // ...
  ],
}).compile();
```

This is why unit tests need no `SUPABASE_URL` / `SUPABASE_ANON_KEY` and no
network access.
