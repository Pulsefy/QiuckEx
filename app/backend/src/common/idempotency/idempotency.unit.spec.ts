import { CallHandler, ExecutionContext } from "@nestjs/common";
import { lastValueFrom, Observable, of, throwError } from "rxjs";

import { AppConfigService } from "../../config/app-config.service";
import { IdempotencyStore } from "./idempotency-store.service";
import {
  IdempotencyInterceptor,
  IDEMPOTENCY_KEY_HEADER,
} from "./idempotency.interceptor";

describe("IdempotencyStore", () => {
  const buildStore = (retentionHours = 24): IdempotencyStore =>
    new IdempotencyStore({
      idempotencyRetentionHours: retentionHours,
    } as unknown as AppConfigService);

  it("begins a fresh key as PENDING and returns undefined", () => {
    const store = buildStore();
    expect(store.begin("key-1", "fp-1")).toBeUndefined();
    expect(store.peek("key-1")?.status).toBe("PENDING");
    expect(store.peek("key-1")?.fingerprint).toBe("fp-1");
  });

  it("returns the existing record when the key is reused before completion", () => {
    const store = buildStore();
    store.begin("key-1", "fp-1");
    const existing = store.begin("key-1", "fp-other");
    expect(existing?.status).toBe("PENDING");
    expect(existing?.fingerprint).toBe("fp-1");
  });

  it("treats an expired key as fresh on begin()", () => {
    const store = buildStore(0); // retention of 0ms => immediate expiry
    store.begin("key-1", "fp-1");
    expect(store.begin("key-1", "fp-2")).toBeUndefined();
    expect(store.peek("key-1")?.fingerprint).toBe("fp-2");
  });

  it("complete() stores a replayable COMPLETED record", () => {
    const store = buildStore();
    store.begin("key-1", "fp-1");
    store.complete("key-1", 201, { ok: true });
    const record = store.peek("key-1");
    expect(record?.status).toBe("COMPLETED");
    expect(record?.statusCode).toBe(201);
    expect(record?.responseBody).toEqual({ ok: true });
    expect(record?.fingerprint).toBe("fp-1");
  });

  it("release() removes only PENDING records", () => {
    const store = buildStore();
    store.begin("pending-key", "fp-a");
    store.begin("done-key", "fp-b");
    store.complete("done-key", 200, {});

    store.release("pending-key");
    expect(store.peek("pending-key")).toBeUndefined();

    store.release("done-key");
    expect(store.peek("done-key")).toBeDefined();
  });

  it("sweepExpired() removes expired records and keeps live ones", () => {
    const store = buildStore();
    store.begin("live", "fp-live");
    store.begin("stale", "fp-stale");

    // Force the stale record into the past.
    const stale = store.peek("stale");
    (store as unknown as { records: Map<string, { expiresAt: number }> })
      .records.set("stale", {
        ...(stale as { fingerprint: string; status: "PENDING" }),
        expiresAt: Date.now() - 1,
      });

    expect(store.sweepExpired()).toBe(1);
    expect(store.peek("stale")).toBeUndefined();
    expect(store.peek("live")).toBeDefined();
  });
});

describe("IdempotencyInterceptor", () => {
  let store: IdempotencyStore;
  let interceptor: IdempotencyInterceptor;
  let handlerCalls: number;

  const buildContext = (
    method: string,
    url: string,
    body: unknown,
    headers: Record<string, string> = {},
  ): {
    context: ExecutionContext;
    res: Record<string, unknown>;
    req: Record<string, unknown>;
  } => {
    // Express header lookups are case-insensitive; emulate that here.
    const normalizedHeaders: Record<string, string> = {};
    for (const [name, value] of Object.entries(headers)) {
      normalizedHeaders[name.toLowerCase()] = value;
    }
    const req: Record<string, unknown> = {
      method,
      originalUrl: url,
      body,
      header: (name: string) => normalizedHeaders[name.toLowerCase()],
    };
    const res: Record<string, unknown> = {
      statusCode: method === "POST" ? 201 : 200,
      status(code: number) {
        this.statusCode = code;
        return this;
      },
    };
    const context = {
      getType: () => "http",
      switchToHttp: () => ({
        getRequest: () => req,
        getResponse: () => res,
      }),
    } as unknown as ExecutionContext;
    return { context, res, req };
  };

  beforeEach(() => {
    store = new IdempotencyStore({
      idempotencyRetentionHours: 24,
    } as unknown as AppConfigService);
    interceptor = new IdempotencyInterceptor(store);
    handlerCalls = 0;
  });

  const runHandler = (result: unknown) =>
    ({
      handle: () => {
        handlerCalls += 1;
        return of(result);
      },
    }) as unknown as CallHandler;

  /**
   * Runs the interceptor and returns the thrown HttpException payload
   * (or undefined when no error occurred). intercept() throws synchronously
   * for validation/conflict paths and rejects via the observable otherwise,
   * so both are normalized here.
   */
  const interceptError = async (
    ctx: ExecutionContext,
    handler: CallHandler = runHandler({}),
  ): Promise<{ response?: { code?: string } } | undefined> => {
    try {
      await lastValueFrom(interceptor.intercept(ctx, handler));
      return undefined;
    } catch (err) {
      return err as { response?: { code?: string } };
    }
  };

  it("passes through requests without an Idempotency-Key header", async () => {
    const { context } = buildContext("POST", "/transactions/compose", { a: 1 });
    await lastValueFrom(
      interceptor.intercept(context, runHandler({ done: true })),
    );
    expect(handlerCalls).toBe(1);
    expect(store.size()).toBe(0);
  });

  it("rejects empty keys with IDEMPOTENCY_KEY_INVALID", async () => {
    const { context } = buildContext(
      "POST",
      "/transactions/compose",
      { a: 1 },
      { [IDEMPOTENCY_KEY_HEADER]: "   " },
    );
    const err = await interceptError(context);
    expect(err?.response?.code).toBe("IDEMPOTENCY_KEY_INVALID");
  });

  it("rejects oversized keys with IDEMPOTENCY_KEY_INVALID", async () => {
    const { context } = buildContext(
      "POST",
      "/transactions/compose",
      { a: 1 },
      { [IDEMPOTENCY_KEY_HEADER]: "k".repeat(129) },
    );
    const err = await interceptError(context);
    expect(err?.response?.code).toBe("IDEMPOTENCY_KEY_INVALID");
  });

  it("executes once and replays the cached response for identical key+body", async () => {
    const first = buildContext(
      "POST",
      "/transactions/submit",
      { signedXdr: "AAA" },
      { [IDEMPOTENCY_KEY_HEADER]: "order-1" },
    );
    const second = buildContext(
      "POST",
      "/transactions/submit",
      { signedXdr: "AAA" },
      { [IDEMPOTENCY_KEY_HEADER]: "order-1" },
    );

    const firstResult = await lastValueFrom(
      interceptor.intercept(first.context, runHandler({ hash: "H1" })),
    );
    expect(firstResult).toEqual({ hash: "H1" });

    // Second request must not reach the handler again.
    const secondResult = await lastValueFrom(
      interceptor.intercept(second.context, runHandler({ hash: "NEVER" })),
    );
    expect(secondResult).toEqual({ hash: "H1" });
    expect(handlerCalls).toBe(1);
  });

  it("replays the original HTTP status code", async () => {
    const first = buildContext(
      "POST",
      "/transactions/compose",
      { a: 1 },
      { [IDEMPOTENCY_KEY_HEADER]: "status-key" },
    );
    // Simulate Nest applying @HttpCode(202) before emitting the body.
    const handler = {
      handle: () =>
        new Observable((sub) => {
          (first.res.status as (code: number) => unknown)(202);
          sub.next({ created: true });
          sub.complete();
        }),
    } as unknown as CallHandler;
    await lastValueFrom(interceptor.intercept(first.context, handler));
    expect(store.peek("status-key")?.statusCode).toBe(202);

    const replay = buildContext(
      "POST",
      "/transactions/compose",
      { a: 1 },
      { [IDEMPOTENCY_KEY_HEADER]: "status-key" },
    );
    await lastValueFrom(
      interceptor.intercept(replay.context, runHandler({ never: true })),
    );
    expect((replay.res as { statusCode?: number }).statusCode).toBe(202);
    // The replay path never invoked the handler (first request used the
    // deferred handler above, so total handler invocations remain 0).
    expect(handlerCalls).toBe(0);
  });

  it("conflicts when the same key is reused with a different body", async () => {
    const first = buildContext(
      "POST",
      "/transactions/submit",
      { signedXdr: "AAA" },
      { [IDEMPOTENCY_KEY_HEADER]: "dup-1" },
    );
    await lastValueFrom(interceptor.intercept(first.context, runHandler({})));

    const second = buildContext(
      "POST",
      "/transactions/submit",
      { signedXdr: "BBB" }, // different payload, same key
      { [IDEMPOTENCY_KEY_HEADER]: "dup-1" },
    );
    const err = await interceptError(second.context);
    expect(err?.response?.code).toBe("IDEMPOTENCY_KEY_REUSED");
    expect(handlerCalls).toBe(1);
  });

  it("conflicts when the same key is reused on a different endpoint", async () => {
    const first = buildContext(
      "POST",
      "/transactions/compose",
      { a: 1 },
      { [IDEMPOTENCY_KEY_HEADER]: "route-key" },
    );
    await lastValueFrom(interceptor.intercept(first.context, runHandler({})));

    const second = buildContext(
      "POST",
      "/fiat-ramps/deposit",
      { a: 1 }, // identical body but different route
      { [IDEMPOTENCY_KEY_HEADER]: "route-key" },
    );
    const err = await interceptError(second.context);
    expect(err?.response?.code).toBe("IDEMPOTENCY_KEY_REUSED");
  });

  it("reports in-progress conflicts for concurrent duplicate requests", async () => {
    const { context, req } = buildContext(
      "POST",
      "/links/metadata",
      { amount: 10 },
      { [IDEMPOTENCY_KEY_HEADER]: "race-key" },
    );
    // Seed the store exactly as an in-flight identical request would have.
    const fingerprint = (
      interceptor as unknown as {
        buildFingerprint: (r: unknown) => string;
      }
    ).buildFingerprint(req);
    store.begin("race-key", fingerprint);

    const err = await interceptError(context);
    expect(err?.response?.code).toBe("IDEMPOTENCY_KEY_IN_PROGRESS");
  });

  it("serializes concurrent duplicates: in-flight conflict then clean replay", async () => {
    let resolveFirst!: (value: unknown) => void;
    const deferredHandler = {
      handle: () =>
        new Observable((sub) => {
          handlerCalls += 1;
          resolveFirst = (value: unknown) => {
            sub.next(value);
            sub.complete();
          };
        }),
    } as unknown as CallHandler;

    const first = buildContext(
      "POST",
      "/transactions/submit",
      { signedXdr: "RACE" },
      { [IDEMPOTENCY_KEY_HEADER]: "race-2" },
    );
    // Subscribing starts execution but leaves the key PENDING.
    const firstPromise = lastValueFrom(
      interceptor.intercept(first.context, deferredHandler),
    );

    const duplicate = buildContext(
      "POST",
      "/transactions/submit",
      { signedXdr: "RACE" },
      { [IDEMPOTENCY_KEY_HEADER]: "race-2" },
    );
    const dupErr = await interceptError(duplicate.context);
    expect(dupErr?.response?.code).toBe("IDEMPOTENCY_KEY_IN_PROGRESS");

    resolveFirst({ hash: "H-RACE" });
    await expect(firstPromise).resolves.toEqual({ hash: "H-RACE" });

    // Once completed, an identical retry replays without executing again.
    const replay = buildContext(
      "POST",
      "/transactions/submit",
      { signedXdr: "RACE" },
      { [IDEMPOTENCY_KEY_HEADER]: "race-2" },
    );
    const replayed = await lastValueFrom(
      interceptor.intercept(replay.context, runHandler({ never: true })),
    );
    expect(replayed).toEqual({ hash: "H-RACE" });
    expect(handlerCalls).toBe(1);
  });

  it("releases the key after a failed handler so clients can retry", async () => {
    const failingHandler = {
      handle: () => throwError(() => new Error("horizon down")),
    } as unknown as CallHandler;
    const first = buildContext(
      "POST",
      "/transactions/submit",
      { x: 1 },
      { [IDEMPOTENCY_KEY_HEADER]: "retry-key" },
    );

    await expect(
      lastValueFrom(interceptor.intercept(first.context, failingHandler)),
    ).rejects.toThrow("horizon down");
    expect(store.peek("retry-key")).toBeUndefined();

    // Retry with the same key now executes normally.
    const retry = buildContext(
      "POST",
      "/transactions/submit",
      { x: 1 },
      { [IDEMPOTENCY_KEY_HEADER]: "retry-key" },
    );
    const result = await lastValueFrom(
      interceptor.intercept(retry.context, runHandler({ ok: true })),
    );
    expect(result).toEqual({ ok: true });
    expect(handlerCalls).toBe(1);
  });

  it("ignores non-mutating methods entirely", async () => {
    const { context } = buildContext(
      "GET",
      "/links/metadata",
      undefined,
      { [IDEMPOTENCY_KEY_HEADER]: "get-key" },
    );
    await lastValueFrom(
      interceptor.intercept(context, runHandler({ list: [] })),
    );
    expect(handlerCalls).toBe(1);
    expect(store.size()).toBe(0);
  });

  it("fingerprints include the request URL so different routes conflict", () => {
    const fpA = (
      interceptor as unknown as {
        buildFingerprint: (req: { method: string; originalUrl: string; body: unknown }) => string;
      }
    ).buildFingerprint({ method: "POST", originalUrl: "/a", body: { v: 1 } });
    const fpB = (
      interceptor as unknown as {
        buildFingerprint: (req: { method: string; originalUrl: string; body: unknown }) => string;
      }
    ).buildFingerprint({ method: "POST", originalUrl: "/b", body: { v: 1 } });
    expect(fpA).not.toBe(fpB);
  });
});
