import AsyncStorage from "@react-native-async-storage/async-storage";
import NetInfo from "@react-native-community/netinfo";
import {
  getOfflineQueue,
  enqueueAction,
  dequeueAction,
  clearOfflineQueue,
  updateQueueItem,
  retryQueuedAction,
  processOfflineQueue,
  registerConflictPolicy,
  getConflictPolicy,
  registerActionHandler,
  confirmQueuedAction,
  discardQueuedAction,
  ActionError,
  resetRegistries,
} from "../services/offline-queue";

// ---------------------------------------------------------------------------
// Mocks
// ---------------------------------------------------------------------------

jest.mock("@react-native-async-storage/async-storage", () => {
  let store: Record<string, string> = {};
  return {
    getItem: jest.fn(async (key: string) => store[key] ?? null),
    setItem: jest.fn(async (key: string, value: string) => {
      store[key] = value;
    }),
    removeItem: jest.fn(async (key: string) => {
      delete store[key];
    }),
    clear: jest.fn(async () => {
      store = {};
    }),
  };
});

jest.mock("@react-native-community/netinfo", () => ({
  fetch: jest.fn(),
}));

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

beforeEach(async () => {
  jest.clearAllMocks();
  await AsyncStorage.clear();
  resetRegistries();
});

// ---------------------------------------------------------------------------
// 1. Core CRUD
// ---------------------------------------------------------------------------

describe("Core CRUD", () => {
  it("starts with an empty queue", async () => {
    expect(await getOfflineQueue()).toEqual([]);
  });

  it("enqueues an action with pending status and correct shape", async () => {
    const action = await enqueueAction("mock-success", { key: "value" });

    expect(action.id).toMatch(/^act_/);
    expect(action.type).toBe("mock-success");
    expect(action.payload).toEqual({ key: "value" });
    expect(action.status).toBe("pending");
    expect(action.attempts).toBe(0);
    expect(action.failureReason).toBeNull();
    expect(action.timestamp).toBeLessThanOrEqual(Date.now());
    expect(typeof action.idempotencyKey).toBe("string");
    expect(action.idempotencyKey.length).toBeGreaterThan(0);
    // idempotencyKey is derived from the id — same value, stable across calls
    expect(action.idempotencyKey).toBe(action.id);
    expect(action.outcome).toBeNull();

    const queue = await getOfflineQueue();
    expect(queue).toHaveLength(1);
    expect(queue[0]).toEqual(action);
  });

  it("dequeues an action by ID", async () => {
    const a1 = await enqueueAction("mock-success", { id: 1 });
    const a2 = await enqueueAction("mock-failure", { id: 2 });

    await dequeueAction(a1.id);

    const queue = await getOfflineQueue();
    expect(queue).toHaveLength(1);
    expect(queue[0].id).toBe(a2.id);
  });

  it("clears the entire queue", async () => {
    await enqueueAction("mock-success", {});
    await enqueueAction("mock-failure", {});
    await clearOfflineQueue();
    expect(await getOfflineQueue()).toHaveLength(0);
  });

  it("updates metadata fields on a queue item", async () => {
    const action = await enqueueAction("mock-success", { foo: "bar" });
    const updated = await updateQueueItem(action.id, {
      status: "failed",
      attempts: 3,
      failureReason: "Timed out",
    });

    expect(updated?.status).toBe("failed");
    expect(updated?.attempts).toBe(3);
    expect(updated?.failureReason).toBe("Timed out");
  });
});

// ---------------------------------------------------------------------------
// 2. Conflict-policy registry
// ---------------------------------------------------------------------------

describe("Conflict-policy registry", () => {
  it("defaults to retry when no policy is registered", () => {
    expect(getConflictPolicy("unknown-type-xyz")).toBe("retry");
  });

  it("returns the registered policy", () => {
    registerConflictPolicy("send-payment", "require-confirm");
    expect(getConflictPolicy("send-payment")).toBe("require-confirm");
  });

  it("assigns conflictPolicy from registry at enqueue time", async () => {
    registerConflictPolicy("mock-success", "drop");
    const action = await enqueueAction("mock-success", {});
    expect(action.conflictPolicy).toBe("drop");
  });
});

// ---------------------------------------------------------------------------
// 3. Idempotency key
// ---------------------------------------------------------------------------

describe("Idempotency key", () => {
  it("assigns a stable idempotencyKey equal to the action id", async () => {
    const action = await enqueueAction("mock-success", {});
    expect(action.idempotencyKey).toBe(action.id);
  });

  it("passes idempotencyKey to the registered handler", async () => {
    const captured: string[] = [];
    registerActionHandler("idem-test", async (_payload, key) => {
      captured.push(key);
    });

    const action = await enqueueAction("idem-test", {});
    await retryQueuedAction(action.id);

    expect(captured).toHaveLength(1);
    expect(captured[0]).toBe(action.idempotencyKey);
  });
});

// ---------------------------------------------------------------------------
// 4. Success path
// ---------------------------------------------------------------------------

describe("Success path", () => {
  it("marks action as completed with outcome=success", async () => {
    const action = await enqueueAction("mock-success", {});
    const result = await retryQueuedAction(action.id);

    expect(result?.status).toBe("completed");
    expect(result?.outcome).toBe("success");
    expect(result?.attempts).toBe(1);
    expect(result?.failureReason).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// 5. Expired-target conflict
// ---------------------------------------------------------------------------

describe("Expired-target conflict", () => {
  it("drops the action when policy=drop (default for mock-expired-link)", async () => {
    registerConflictPolicy("mock-expired-link", "drop");
    const action = await enqueueAction("mock-expired-link", { linkId: "abc" });
    const result = await retryQueuedAction(action.id);

    expect(result?.status).toBe("completed");
    expect(result?.outcome).toBe("dropped-expired");
    expect(result?.outcomeMessage).toContain("expired");
  });

  it("drops the action when policy=retry (default) and target is expired", async () => {
    registerConflictPolicy("mock-expired-link", "retry");
    const action = await enqueueAction("mock-expired-link", {});
    const result = await retryQueuedAction(action.id);

    expect(result?.status).toBe("completed");
    expect(result?.outcome).toBe("dropped-expired");
  });

  it("surfaces to user for confirmation when policy=require-confirm", async () => {
    registerConflictPolicy("mock-expired-link", "require-confirm");
    const action = await enqueueAction("mock-expired-link", { linkId: "abc" });
    const result = await retryQueuedAction(action.id);

    expect(result?.status).toBe("conflict");
    expect(result?.outcome).toBe("awaiting-user-confirmation");
    expect(result?.outcomeMessage).toBeTruthy();
  });
});

// ---------------------------------------------------------------------------
// 6. Already-applied conflict
// ---------------------------------------------------------------------------

describe("Already-applied conflict", () => {
  it("always drops regardless of policy", async () => {
    // Even with require-confirm, already-applied is always auto-dropped
    // because the work is done — no decision needed.
    for (const policy of ["retry", "drop", "require-confirm"] as const) {
      await AsyncStorage.clear();
      registerConflictPolicy("mock-already-applied", policy);
      const action = await enqueueAction("mock-already-applied", {});
      const result = await retryQueuedAction(action.id);

      expect(result?.status).toBe("completed");
      expect(result?.outcome).toBe("dropped-already-applied");
    }
  });
});

// ---------------------------------------------------------------------------
// 7. Permanently-failing action
// ---------------------------------------------------------------------------

describe("Permanently-failing action", () => {
  it("drops the action when policy=drop", async () => {
    registerConflictPolicy("mock-permanent-failure", "drop");
    const action = await enqueueAction("mock-permanent-failure", {});
    const result = await retryQueuedAction(action.id);

    expect(result?.status).toBe("completed");
    expect(result?.outcome).toBe("dropped-permanent-failure");
  });

  it("surfaces to user when policy=require-confirm", async () => {
    registerConflictPolicy("mock-permanent-failure", "require-confirm");
    const action = await enqueueAction("mock-permanent-failure", {});
    const result = await retryQueuedAction(action.id);

    expect(result?.status).toBe("conflict");
    expect(result?.outcome).toBe("awaiting-user-confirmation");
  });

  it("treats the failure as transient when policy=retry", async () => {
    registerConflictPolicy("mock-permanent-failure", "retry");
    const action = await enqueueAction("mock-permanent-failure", {});
    const result = await retryQueuedAction(action.id);

    // policy=retry: no special classification → falls through to transient
    expect(result?.status).toBe("failed");
    expect(result?.outcome).toBe("failed");
  });
});

// ---------------------------------------------------------------------------
// 8. Transient failure (regular network / server error)
// ---------------------------------------------------------------------------

describe("Transient failure", () => {
  it("marks action as failed with outcome=failed", async () => {
    const action = await enqueueAction("mock-failure", {});
    const result = await retryQueuedAction(action.id);

    expect(result?.status).toBe("failed");
    expect(result?.outcome).toBe("failed");
    expect(result?.attempts).toBe(1);
    expect(result?.failureReason).toBe("Simulated network timeout/offline error");
  });
});

// ---------------------------------------------------------------------------
// 9. User-confirmation flow
// ---------------------------------------------------------------------------

describe("User-confirmation flow", () => {
  it("confirmQueuedAction resets a conflicted action to pending", async () => {
    registerConflictPolicy("mock-expired-link", "require-confirm");
    const action = await enqueueAction("mock-expired-link", {});
    await retryQueuedAction(action.id); // → conflict

    const confirmed = await confirmQueuedAction(action.id);
    expect(confirmed?.status).toBe("pending");
    expect(confirmed?.outcome).toBe("user-confirmed");
  });

  it("discardQueuedAction marks a conflicted action as completed/discarded", async () => {
    registerConflictPolicy("mock-expired-link", "require-confirm");
    const action = await enqueueAction("mock-expired-link", {});
    await retryQueuedAction(action.id); // → conflict

    const discarded = await discardQueuedAction(action.id);
    expect(discarded?.status).toBe("completed");
    expect(discarded?.outcome).toBe("user-discarded");
  });

  it("confirmed actions are re-processed on the next processOfflineQueue run", async () => {
    // Give mock-expired-link a handler that succeeds after user confirms
    let callCount = 0;
    registerActionHandler("mock-confirmed-retry", async () => {
      callCount++;
    });
    registerConflictPolicy("mock-confirmed-retry", "require-confirm");

    const action = await enqueueAction("mock-confirmed-retry", {});
    // Simulate a transient failure that lands it in conflict state manually
    await updateQueueItem(action.id, {
      status: "conflict",
      outcome: "awaiting-user-confirmation",
    });

    // User confirms
    await confirmQueuedAction(action.id);

    // processOfflineQueue should now pick it up (status=pending)
    await processOfflineQueue();

    expect(callCount).toBe(1);
    const queue = await getOfflineQueue();
    expect(queue[0].status).toBe("completed");
  });
});

// ---------------------------------------------------------------------------
// 10. Outcome visibility (inspector audit trail)
// ---------------------------------------------------------------------------

describe("Outcome visibility", () => {
  it("persists outcome and outcomeMessage on the queue entry", async () => {
    const action = await enqueueAction("mock-success", {});
    await retryQueuedAction(action.id);

    const queue = await getOfflineQueue();
    const entry = queue.find((i) => i.id === action.id)!;
    expect(entry.outcome).toBe("success");
    expect(typeof entry.outcomeMessage).toBe("string");
  });

  it("records outcome=dropped-expired after an expired-target drop", async () => {
    registerConflictPolicy("mock-expired-link", "drop");
    const action = await enqueueAction("mock-expired-link", {});
    await retryQueuedAction(action.id);

    const queue = await getOfflineQueue();
    const entry = queue.find((i) => i.id === action.id)!;
    expect(entry.outcome).toBe("dropped-expired");
    expect(entry.outcomeMessage).toBeTruthy();
  });
});

// ---------------------------------------------------------------------------
// 11. processOfflineQueue — batch processing
// ---------------------------------------------------------------------------

describe("processOfflineQueue", () => {
  it("processes all pending and failed actions sequentially", async () => {
    const a1 = await enqueueAction("mock-success", { n: 1 });
    const a2 = await enqueueAction("mock-failure", { n: 2 });
    const a3 = await enqueueAction("mock-success", { n: 3 });

    // Pre-mark a3 as completed so it should be skipped
    await updateQueueItem(a3.id, { status: "completed" });

    await processOfflineQueue();

    const queue = await getOfflineQueue();
    const map = new Map(queue.map((i) => [i.id, i]));

    expect(map.get(a1.id)?.status).toBe("completed");
    expect(map.get(a2.id)?.status).toBe("failed");
    expect(map.get(a3.id)?.status).toBe("completed"); // untouched
    expect(map.get(a1.id)?.attempts).toBe(1);
    expect(map.get(a2.id)?.attempts).toBe(1);
    expect(map.get(a3.id)?.attempts).toBe(0);
  });

  it("skips conflict-status actions (awaiting user input)", async () => {
    const action = await enqueueAction("mock-success", {});
    await updateQueueItem(action.id, {
      status: "conflict",
      outcome: "awaiting-user-confirmation",
    });

    await processOfflineQueue();

    const queue = await getOfflineQueue();
    // Still in conflict — not touched by batch run
    expect(queue[0].status).toBe("conflict");
    expect(queue[0].attempts).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// 12. mock-payment (network-aware built-in handler)
// ---------------------------------------------------------------------------

describe("mock-payment built-in handler", () => {
  it("fails when device is offline", async () => {
    (NetInfo.fetch as jest.Mock).mockResolvedValue({ isConnected: false });
    const action = await enqueueAction("mock-payment", { amount: "10.00" });
    const result = await retryQueuedAction(action.id);

    expect(result?.status).toBe("failed");
    expect(result?.failureReason).toContain("offline");
  });

  it("succeeds when device is online", async () => {
    (NetInfo.fetch as jest.Mock).mockResolvedValue({ isConnected: true });
    const action = await enqueueAction("mock-payment", { amount: "10.00" });
    const result = await retryQueuedAction(action.id);

    expect(result?.status).toBe("completed");
    expect(result?.outcome).toBe("success");
  });
});

// ---------------------------------------------------------------------------
// 13. ActionError — structured error propagation
// ---------------------------------------------------------------------------

describe("ActionError", () => {
  it("carries a statusCode and is classified correctly", () => {
    const err = new ActionError("Payment link expired", 410);
    expect(err.message).toBe("Payment link expired");
    expect(err.statusCode).toBe(410);
    expect(err.name).toBe("ActionError");
  });

  it("classifies a 409 handler error as already-applied", async () => {
    registerActionHandler("conflict-409", async () => {
      throw new ActionError("Conflict", 409);
    });
    const action = await enqueueAction("conflict-409", {});
    const result = await retryQueuedAction(action.id);

    expect(result?.outcome).toBe("dropped-already-applied");
  });

  it("classifies a 410 handler error as expired-target and drops it", async () => {
    registerConflictPolicy("gone-410", "drop");
    registerActionHandler("gone-410", async () => {
      throw new ActionError("Resource gone", 410);
    });
    const action = await enqueueAction("gone-410", {});
    const result = await retryQueuedAction(action.id);

    expect(result?.outcome).toBe("dropped-expired");
  });
});
