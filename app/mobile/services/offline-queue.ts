import AsyncStorage from "@react-native-async-storage/async-storage";
import NetInfo from "@react-native-community/netinfo";

export interface QueuedAction {
  id: string;
  type: string;
  payload: any;
  timestamp: number;
  status: "pending" | "retrying" | "failed" | "completed";
  failureReason?: string | null;
  attempts: number;
}

const OFFLINE_QUEUE_KEY = "quickex.offline-queue.v1";

/**
 * Retrieves all queued actions from local storage.
 */
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

/**
 * Saves the entire queue array to local storage.
 */
export async function saveOfflineQueue(queue: QueuedAction[]): Promise<void> {
  try {
    await AsyncStorage.setItem(OFFLINE_QUEUE_KEY, JSON.stringify(queue));
  } catch (error) {
    console.error("Failed to save offline queue", error);
  }
}

/**
 * Enqueues a new offline action with status 'pending'.
 */
export async function enqueueAction(
  type: string,
  payload: any,
): Promise<QueuedAction> {
  const queue = await getOfflineQueue();
  const newAction: QueuedAction = {
    id: `act_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`,
    type,
    payload,
    timestamp: Date.now(),
    status: "pending",
    attempts: 0,
    failureReason: null,
  };
  queue.push(newAction);
  await saveOfflineQueue(queue);
  return newAction;
}

/**
 * Dequeues (removes) a specific action by ID from the queue.
 */
export async function dequeueAction(id: string): Promise<void> {
  const queue = await getOfflineQueue();
  const nextQueue = queue.filter((item) => item.id !== id);
  await saveOfflineQueue(nextQueue);
}

/**
 * Wipes the entire offline queue.
 */
export async function clearOfflineQueue(): Promise<void> {
  try {
    await AsyncStorage.removeItem(OFFLINE_QUEUE_KEY);
  } catch (error) {
    console.error("Failed to clear offline queue", error);
  }
}

/**
 * Updates a queue item's metadata and writes to storage.
 */
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

// Handler registry for registering real action consumers
type ActionHandler = (payload: any) => Promise<void>;
const handlers: Record<string, ActionHandler> = {};

export function registerActionHandler(type: string, handler: ActionHandler) {
  handlers[type] = handler;
}

/**
 * Resolves/executes the target action logic based on type.
 */
export async function executeAction(action: QueuedAction): Promise<void> {
  const handler = handlers[action.type];
  if (handler) {
    await handler(action.payload);
    return;
  }

  // Built-in mock handlers for development debugging
  if (action.type === "mock-success") {
    await new Promise((resolve) => setTimeout(resolve, 800));
    return;
  }

  if (action.type === "mock-failure") {
    await new Promise((resolve) => setTimeout(resolve, 800));
    throw new Error("Simulated network timeout/offline error");
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

/**
 * Retries a specific queued action, updating its attempts and status.
 */
export async function retryQueuedAction(id: string): Promise<QueuedAction | null> {
  const queue = await getOfflineQueue();
  const action = queue.find((item) => item.id === id);
  if (!action) return null;

  await updateQueueItem(id, { status: "retrying", failureReason: null });

  try {
    await executeAction(action);
    const updated = await updateQueueItem(id, {
      status: "completed",
      attempts: action.attempts + 1,
      failureReason: null,
    });
    return updated;
  } catch (error: any) {
    const reason = error?.message || "Unknown error occurred";
    const updated = await updateQueueItem(id, {
      status: "failed",
      attempts: action.attempts + 1,
      failureReason: reason,
    });
    return updated;
  }
}

/**
 * Iterates through all pending/failed actions and retries them sequentially.
 */
export async function processOfflineQueue(): Promise<void> {
  const queue = await getOfflineQueue();
  const pendingOrFailed = queue.filter(
    (item) => item.status === "pending" || item.status === "failed",
  );

  for (const item of pendingOrFailed) {
    await retryQueuedAction(item.id);
  }
}
