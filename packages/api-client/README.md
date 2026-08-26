# @quickex/api-client

A generated, **typed** client for the QuickEx backend, produced from the
OpenAPI spec at `app/backend/docs/openapi.yaml`.

Keeping the client generated (instead of hand-writing request/response types)
means client types can no longer silently diverge from the backend routes and
base URL.

## Regenerate (single command)

From the repo root:

```bash
pnpm api-client:generate
```

Or directly inside this package:

```bash
cd packages/api-client
npm run regenerate        # runs generate + build
```

This regenerates `src/schemas.d.ts` from the spec and rebuilds the runtime
client in `dist/`. Commit both — CI fails when they are out of date.

## CI

`.github/workflows/api-client.yml` regenerates the client on every change to
the spec or this package and fails the build if the committed output differs
from a fresh generation.

## Usage

The package ships a thin wrapper around
[`openapi-fetch`](https://github.com/openapi-ts/openapi-fetch) typed by the
generated `paths`.

### Frontend (Next.js)

```ts
import { getQuickexApiBase } from "@/lib/api";
import { createQuickexClient } from "@quickex/api-client";

const client = createQuickexClient({ baseUrl: getQuickexApiBase() });

const { data, error, response } = await client.GET("/payments/recent", {
  params: { query: { address, limit } },
});
```

See `app/frontend/src/hooks/activityFeedApi.ts` for a real call site.

### Mobile (Expo)

```ts
import { createQuickexClient } from "@quickex/api-client";
import { ENVIRONMENTS } from "../config/environment";

const client = createQuickexClient({ baseUrl: ENVIRONMENTS.production.apiUrl });
const { data } = await client.GET("/status");
```

See `app/mobile/src/services/quickexApi.ts` for a real call site.

## Type-only access

The raw generated types are available without the runtime dependency:

```ts
import type { paths } from "@quickex/api-client/schemas";
```
