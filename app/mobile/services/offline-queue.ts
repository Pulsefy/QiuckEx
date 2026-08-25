import AsyncStorage from "@react-native-async-storage/async-storage";
import NetInfo from "@react-native-community/netinfo";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/**
 * How the queue should behave when server state has changed underneath a
 * queued action before it can be replayed.
 *
 * - retry            Re-attempt without any conflict checks (pure network
 *                    failures, idempotent writes already guarded server-side).
 * - drop             Silently discard the action when a definitive conflict is
 *                    detected (e.g. already-applied / permanent server error).
 * - require-confirm  Pause replay and surface the conflict to the user so they
 *                    can decide whether to proceed or discard.
 */
export type ConflictPolicy = "retry" | "drop" | "require-confirm";

/**
 * Terminal or informational outcome stored once an action finishes processing.
 * Persisted on the queue entry so the inspector can show a full audit trail.
 */
export type ActionOutcome =
  | "success"
  | "dropped-expired"
  | "dropped-already-applied"
  | "dropped-permanent-failure"
  | "awaiting-user-confirmation"
  | "user-confirmed"
  | "user-discarded"
  | "failed";

export interface QueuedAction {
  id: string;
  type: string;
  payload: unknown;
  /** Wall-clock time the action was originally created (ms since epoch). */
  timestamp: number;
  status: "pending" | "retrying" | "failed" | "completed" | "conflict";
  failureReason?: string | null;
  attempts: number;
  /**
   * Conflict policy declared by the action type at enqueue time.
   * Defaults to "retry" for backwards-compat with entries that pre-date this
   * field.
   */
  conflictPolicy: ConflictPolicy;
  /**
   * Stable key forwarded to the backend as the `Idempotency-Key` header so
   * that duplicate replays are safely deduplicated server-side.
   */
  idempotencyKey: string;
  /** Terminal outcome recorded after processing. */
  outcome?: ActionOutcome | null;
  /** Human-readable summary shown in the inspector after processing. */
  outcomeMessage?: string | null;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const OFFLINE_QUEUE_KEY = "quickex.offline-queue.v1";

/**
 * HTTP status codes that indicate the server definitively rejected the action
 * and retrying with the same payload will never succeed.
 */
const PERMANENT_FAILURE_STATUSES = new Set([400, 404, 409, 410, 422]);

// ---------------------------------------------------------------------------
// Conflict-policy registry
// ---------------------------------------------------------------------------

/**
 * Each action type can declare a conflict policy by calling
 * `registerConflictPolicy` at module initialisation time.
 *
 * Types that do not register default to "retry".
 */
const conflictPolicies: Record<string, ConflictPolicy> = {};

export function registerConflictPolicy(
  type: string,
  policy: ConflictPolicy,
): void {
  conflictPolicies[type] = policy;
}

export function getConflictPolicy(type: string): ConflictPolicy {
  return conflictPolicies[type] ?? "retry";
}

// ---------------------------------------------------------------------------
// Storage helpers
// ---------------------------------------------------------------------------

export async function getOfflineQueue(): Promise<QueuedAction[]> {
  try {
    const raw = await AsyncStorage.getItem(OFFLINE_QUEUE_KEY);
    if (!raw) return [];
    return JSON.parse(raw) as QueuedAction[];
  } catch (error) {
    console.error("Failed to load offline queue", error);
    return [];
  }
}

export async function saveOfflineQueue(queue: QueuedAction[]): Promise<void> {
  try {
    await AsyncStorage.setItem(OFFLINE_QUEUE_KEY, JSON.stringify(queue));
  } catch (error) {
    console.error("Failed to save offline queue", error);
  }
}

// ---------------------------------------------------------------------------
// CRUD helpers
// ---------------------------------------------------------------------------

/**
 * Enqueues a new offline action.
 *
 * The `conflictPolicy` is looked up from the registry so callers only need to
 * call `registerConflictPolicy` once at app init — not at every enqueue site.
 *
 * An `idempotencyKey` is generated deterministically from the action id so
 * that replays send the same key and the backend can deduplicate them.
 */
export async function enqueueAction(
  type: string,
  payload: unknown,
): Promise<QueuedAction> {
  const queue = await getOfflineQueue();
  const id = `act_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`;
  const newAction: QueuedAction = {
    id,
    type,
    payload,
    timestamp: Date.now(),
    status: "pending",
    attempts: 0,
    failureReason: null,
    conflictPolicy: getConflictPolicy(type),
    // Stable key: derived from the action id so every replay of the same
    // queued entry reuses the identical key and benefits from server-side
    // idempotency deduplication.
    idempotencyKey: id,
    outcome: null,
    outcomeMessage: null,
  };
  queue.push(newAction);
  await saveOfflineQueue(queue);
  return newAction;
}

export async function dequeueAction(id: string): Promise<void> {
  const queue = await getOfflineQueue();
  await saveOfflineQueue(queue.filter((item) => item.id !== id));
}

export async function clearOfflineQueue(): Promise<void> {
  try {
    await AsyncStorage.removeItem(OFFLINE_QUEUE_KEY);
  } catch (error) {
    console.error("Failed to clear offline queue", error);
  }
}

export async function updateQueueItem(
  id: string,
  updates: Partial<Omit<QueuedAction, "id">>,
): Promise<QueuedAction | null> {
  const queue = await getOfflineQueue();
  let updatedItem: QueuedAction | null = null;
  const nextQueue = queue.map((item) => {
    if (item.id === id) {
      updatedItem = { ...item, ...updates };
      return updatedItem;
    }
    return item;
  });
  if (updatedItem) {
    await saveOfflineQueue(nextQueue);
  }
  return updatedItem;
}

// ---------------------------------------------------------------------------
// Action handler registry
// ---------------------------------------------------------------------------

/**
 * Error subclass that action handlers can throw to communicate a structured
 * HTTP-like status to the queue engine.  The engine uses the status code to
 * classify the failure as permanent or transient.
 */
export class ActionError extends Error {
  constructor(
    message: string,
    public readonly statusCode?: number,
  ) {
    super(message);
    this.name = "ActionError";
  }
}

type ActionHandler = (payload: unknown, idempotencyKey: string) => Promise<void>;
const handlers: Record<string, ActionHandler> = {};

export function registerActionHandler(
  type: string,
  handler: ActionHandler,
): void {
  handlers[type] = handler;
}

/**
 * Reset both registries. Intended for use in tests only so each test starts
 * with a clean slate and does not leak policy or handler state.
 */
export function resetRegistries(): void {
  for (const key of Object.keys(conflictPolicies)) {
    delete conflictPolicies[key];
  }
  for (const key of Object.keys(handlers)) {
    delete handlers[key];
  }
}

// ---------------------------------------------------------------------------
// Conflict classification helpers
// ---------------------------------------------------------------------------

/**
 * Inspect an error thrown by an action handler and decide whether it
 * represents a known conflict condition.
 */
function classifyError(error: unknown): {
  isExpiredTarget: boolean;
  isAlreadyApplied: boolean;
  isPermanentFailure: boolean;
} {
  const message =
    error instanceof Error ? error.message.toLowerCase() : String(error).toLowerCase();
  const statusCode =
    error instanceof ActionError ? error.statusCode : undefined;

  const isExpiredTarget =
    message.includes("expired") ||
    message.includes("expir") ||
    statusCode === 410; // Gone

  const isAlreadyApplied =
    message.includes("already") ||
    message.includes("duplicate") ||
    message.includes("idempotency_key_reused") ||
    statusCode === 409;

  const isPermanentFailure =
    (statusCode !== undefined && PERMANENT_FAILURE_STATUSES.has(statusCode)) ||
    message.includes("permanently") ||
    message.includes("invalid payload") ||
    message.includes("validation");

  return { isExpiredTarget, isAlreadyApplied, isPermanentFailure };
}

// ---------------------------------------------------------------------------
// Core execution
// ---------------------------------------------------------------------------

export async function executeAction(action: QueuedAction): Promise<void> {
  const handler = handlers[action.type];
  if (handler) {
    await handler(action.payload, action.idempotencyKey);
    return;
  }

  // Built-in mock handlers (development / QA only) ---

  if (action.type === "mock-success") {
    await new Promise((resolve) => setTimeout(resolve, 800));
    return;
  }

  if (action.type === "mock-failure") {
    await new Promise((resolve) => setTimeout(resolve, 800));
    throw new Error("Simulated network timeout/offline error");
  }

  if (action.type === "mock-expired-link") {
    await new Promise((resolve) => setTimeout(resolve, 200));
    throw new ActionError("Payment link has expired", 410);
  }

  if (action.type === "mock-already-applied") {
    await new Promise((resolve) => setTimeout(resolve, 200));
    throw new ActionError("Transaction already applied: idempotency_key_reused", 409);
  }

  if (action.type === "mock-permanent-failure") {
    await new Promise((resolve) => setTimeout(resolve, 200));
    throw new ActionError("Invalid payload: validation failed", 422);
  }

  if (action.type === "mock-payment") {
    const net = await NetInfo.fetch();
    if (!net.isConnected) {
      throw new Error("Cannot send payment: Device is offline");
    }
    await new Promise((resolve) => setTimeout(resolve, 1000));
    return;
  }

  throw new Error(`No handler registered for action type: ${action.type}`);
}

// ---------------------------------------------------------------------------
// Retry / replay with conflict-policy enforcement
// ---------------------------------------------------------------------------

/**
 * Retry a single queued action, honouring its declared conflict policy.
 *
 * Success path:
 *   - status → completed, outcome → success
 *
 * Failure path — three sub-cases based on error classification + policy:
 *
 *   1. Expired-target conflict with policy=drop or policy=retry
 *      → status=completed, outcome=dropped-expired (log, don't re-surface)
 *
 *   2. Already-applied conflict (idempotent duplicate)
 *      → status=completed, outcome=dropped-already-applied
 *
 *   3. Permanent failure with policy=drop
 *      → status=completed, outcome=dropped-permanent-failure
 *
 *   4. Any conflict with policy=require-confirm
 *      → status=conflict, outcome=awaiting-user-confirmation
 *        (replay is paused until the user calls confirmQueuedAction or
 *        discardQueuedAction)
 *
 *   5. Transient / unknown failure
 *      → status=failed, outcome=failed (caller may retry later)
 */
export async function retryQueuedAction(
  id: string,
): Promise<QueuedAction | null> {
  const queue = await getOfflineQueue();
  const action = queue.find((item) => item.id === id);
  if (!action) return null;

  await updateQueueItem(id, {
    status: "retrying",
    failureReason: null,
    outcome: null,
    outcomeMessage: null,
  });

  try {
    await executeAction(action);

    return updateQueueItem(id, {
      status: "completed",
      attempts: action.attempts + 1,
      failureReason: null,
      outcome: "success",
      outcomeMessage: "Action completed successfully.",
    });
  } catch (error: unknown) {
    const reason =
      error instanceof Error ? error.message : "Unknown error occurred";
    const { isExpiredTarget, isAlreadyApplied, isPermanentFailure } =
      classifyError(error);

    const policy =
      (action.conflictPolicy as ConflictPolicy | undefined) ??
      getConflictPolicy(action.type);

    // --- Already applied: always drop — retrying is pointless and safe to
    //     dismiss because the server already has the record.
    if (isAlreadyApplied) {
      return updateQueueItem(id, {
        status: "completed",
        attempts: action.attempts + 1,
        failureReason: reason,
        outcome: "dropped-already-applied",
        outcomeMessage:
          "This action was already applied on the server. No further action needed.",
      });
    }

    // --- Expired target ---
    if (isExpiredTarget) {
      if (policy === "require-confirm") {
        return updateQueueItem(id, {
          status: "conflict",
          attempts: action.attempts + 1,
          failureReason: reason,
          outcome: "awaiting-user-confirmation",
          outcomeMessage:
            "The target (e.g. payment link) expired while you were offline. Do you still want to proceed?",
        });
      }
      // policy === "drop" or "retry" — drop expired targets automatically
      return updateQueueItem(id, {
        status: "completed",
        attempts: action.attempts + 1,
        failureReason: reason,
        outcome: "dropped-expired",
        outcomeMessage:
          "The target expired while offline. The action has been automatically discarded.",
      });
    }

    // --- Permanent failure ---
    if (isPermanentFailure) {
      if (policy === "require-confirm") {
        return updateQueueItem(id, {
          status: "conflict",
          attempts: action.attempts + 1,
          failureReason: reason,
          outcome: "awaiting-user-confirmation",
          outcomeMessage:
            "This action failed with an error that cannot be retried. Review the details and decide whether to discard it.",
        });
      }
      if (policy === "drop") {
        return updateQueueItem(id, {
          status: "completed",
          attempts: action.attempts + 1,
          failureReason: reason,
          outcome: "dropped-permanent-failure",
          outcomeMessage:
            "Action permanently rejected by server and has been discarded.",
        });
      }
    }

    // --- Transient / unknown failure ---
    return updateQueueItem(id, {
      status: "failed",
      attempts: action.attempts + 1,
      failureReason: reason,
      outcome: "failed",
      outcomeMessage: `Action failed: ${reason}`,
    });
  }
}

// ---------------------------------------------------------------------------
// User-confirmation helpers
// ---------------------------------------------------------------------------

/**
 * Called when the user chooses to proceed with a conflicted action.
 * Resets status to pending so `processOfflineQueue` will replay it.
 */
export async function confirmQueuedAction(
  id: string,
): Promise<QueuedAction | null> {
  return updateQueueItem(id, {
    status: "pending",
    outcome: "user-confirmed",
    outcomeMessage: "User confirmed — will retry on next sync.",
    failureReason: null,
  });
}

/**
 * Called when the user chooses to discard a conflicted action.
 * Marks it completed so it no longer blocks replay runs.
 */
export async function discardQueuedAction(
  id: string,
): Promise<QueuedAction | null> {
  return updateQueueItem(id, {
    status: "completed",
    outcome: "user-discarded",
    outcomeMessage: "Discarded by user.",
    failureReason: null,
  });
}

// ---------------------------------------------------------------------------
// Batch processing
// ---------------------------------------------------------------------------

/**
 * Process all pending and failed actions sequentially.
 *
 * Actions in `conflict` status are intentionally skipped — they are awaiting
 * user input and must not be auto-retried.
 */
export async function processOfflineQueue(): Promise<void> {
  const queue = await getOfflineQueue();
  const actionable = queue.filter(
    (item) => item.status === "pending" || item.status === "failed",
  );

  for (const item of actionable) {
    await retryQueuedAction(item.id);
  }
}
