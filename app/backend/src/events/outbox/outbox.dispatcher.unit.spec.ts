import { OutboxDispatcher } from "./outbox.dispatcher";
import { OutboxMessage, OutboxStatus } from "./outbox.types";

function makeMessage(overrides: Partial<OutboxMessage> = {}): OutboxMessage {
  return {
    id: "id-1",
    eventId: "username:alice",
    aggregateType: "username",
    aggregateId: "alice",
    eventType: "username.claimed",
    payload: { username: "alice", publicKey: "GABC" },
    status: "pending" as OutboxStatus,
    attempts: 0,
    nextAttemptAt: new Date().toISOString(),
    lastError: null,
    createdAt: new Date().toISOString(),
    dispatchedAt: null,
    ...overrides,
  };
}

describe("OutboxDispatcher", () => {
  let repository: jest.Mocked<{
    findPending: jest.Mock;
    markDispatched: jest.Mock;
    recordAttempt: jest.Mock;
    getDepth: jest.Mock;
    getLagSeconds: jest.Mock;
  }>;
  let eventEmitter: { emit: jest.Mock };
  let metrics: {
    setOutboxDepth: jest.Mock;
    setOutboxDispatchLagSeconds: jest.Mock;
    recordOutboxDispatch: jest.Mock;
  };
  let dispatcher: OutboxDispatcher;

  beforeEach(() => {
    repository = {
      findPending: jest.fn(),
      markDispatched: jest.fn().mockResolvedValue(undefined),
      recordAttempt: jest.fn().mockResolvedValue(undefined),
      getDepth: jest.fn().mockResolvedValue(0),
      getLagSeconds: jest.fn().mockResolvedValue(null),
    };
    eventEmitter = { emit: jest.fn() };
    metrics = {
      setOutboxDepth: jest.fn(),
      setOutboxDispatchLagSeconds: jest.fn(),
      recordOutboxDispatch: jest.fn(),
    };
    dispatcher = new OutboxDispatcher(
      repository as never,
      eventEmitter as never,
      metrics as never,
    );
  });

  describe("dispatchBatch", () => {
    it("publishes pending events and marks them dispatched", async () => {
      const msg = makeMessage();
      repository.findPending.mockResolvedValueOnce([msg]);

      const dispatched = await dispatcher.dispatchBatch();

      expect(dispatched).toBe(1);
      expect(eventEmitter.emit).toHaveBeenCalledWith(
        "username.claimed",
        msg.payload,
      );
      expect(repository.markDispatched).toHaveBeenCalledWith(msg.id, expect.any(Date));
      expect(metrics.recordOutboxDispatch).toHaveBeenCalledWith(
        "username.claimed",
        "success",
      );
    });

    it("does not emit when there are no pending events", async () => {
      repository.findPending.mockResolvedValueOnce([]);
      const dispatched = await dispatcher.dispatchBatch();
      expect(dispatched).toBe(0);
      expect(eventEmitter.emit).not.toHaveBeenCalled();
    });

    it("exposes depth and dispatch lag as metrics", async () => {
      repository.findPending.mockResolvedValueOnce([]);
      repository.getDepth.mockResolvedValueOnce(3);
      repository.getLagSeconds.mockResolvedValueOnce(12);
      await dispatcher.dispatchBatch();
      expect(metrics.setOutboxDepth).toHaveBeenCalledWith(3);
      expect(metrics.setOutboxDispatchLagSeconds).toHaveBeenCalledWith(12);
    });
  });

  describe("crash between commit and dispatch (eventual delivery)", () => {
    it("redelivers an event that was committed but never dispatched before a crash", async () => {
      // Simulate the originating transaction committing the outbox row, but the
      // process crashing before the dispatcher ran (no emit happened yet).
      const committed = makeMessage();
      repository.findPending.mockResolvedValueOnce([committed]);
      eventEmitter.emit.mockClear();

      // The dispatcher later starts and must eventually deliver the event.
      const dispatched = await dispatcher.dispatchBatch();

      expect(dispatched).toBe(1);
      expect(eventEmitter.emit).toHaveBeenCalledTimes(1);
      expect(eventEmitter.emit).toHaveBeenCalledWith(
        "username.claimed",
        committed.payload,
      );
      expect(repository.markDispatched).toHaveBeenCalledWith(
        committed.id,
        expect.any(Date),
      );
    });

    it("recovers after a transient emitter failure on the next poll", async () => {
      const msg = makeMessage();
      repository.findPending
        .mockResolvedValueOnce([msg])
        // second poll after the in-memory "crash" still sees the same row
        .mockResolvedValueOnce([{ ...msg, attempts: 1 }]);

      // First tick: emitter throws, attempt recorded, not dispatched.
      eventEmitter.emit.mockImplementationOnce(() => {
        throw new Error("broker unavailable");
      });
      const first = await dispatcher.dispatchBatch();
      expect(first).toBe(0);
      expect(repository.markDispatched).not.toHaveBeenCalled();
      expect(repository.recordAttempt).toHaveBeenCalledWith(
        msg.id,
        "broker unavailable",
        1,
        false,
        expect.any(Date),
      );
      expect(metrics.recordOutboxDispatch).toHaveBeenCalledWith(
        "username.claimed",
        "retry",
      );

      // Second tick: emitter healthy, event delivered.
      eventEmitter.emit.mockImplementation(() => true);
      const second = await dispatcher.dispatchBatch();
      expect(second).toBe(1);
      expect(repository.markDispatched).toHaveBeenCalledWith(
        msg.id,
        expect.any(Date),
      );
    });

    it("moves the row to the dead-letter state after exhausting retries", async () => {
      const msg = makeMessage({ attempts: 24 });
      repository.findPending.mockResolvedValueOnce([msg]);
      eventEmitter.emit.mockImplementation(() => {
        throw new Error("permanent failure");
      });

      await dispatcher.dispatchBatch();

      expect(repository.markDispatched).not.toHaveBeenCalled();
      expect(repository.recordAttempt).toHaveBeenCalledWith(
        msg.id,
        "permanent failure",
        25,
        true,
        expect.any(Date),
      );
      expect(metrics.recordOutboxDispatch).toHaveBeenCalledWith(
        "username.claimed",
        "dead",
      );
    });
  });
});
