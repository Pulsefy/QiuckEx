import { OutboxRepository } from "./outbox.repository";
import {
  buildDeterministicEventId,
  createOutboxId,
  OutboxStatus,
} from "./outbox.types";

class FakeClient {
  public inserted: Record<string, unknown>[] = [];
  public updated: Record<string, unknown>[] = [];
  public selected: unknown[] = [];
  private seq = 0;

  from() {
    return {
      insert: (row: Record<string, unknown>) => {
        this.inserted.push(row);
        return {
          select: () => ({
            single: () => ({
              data: { ...row, id: row.id ?? "generated-id" },
              error: null,
            }),
          }),
        };
      },
      update: (values: Record<string, unknown>) => {
        this.updated.push(values);
        return {
          eq: () => ({ error: null }),
        };
      },
      select: (_cols?: string, opts?: { count?: string }) => {
        if (opts?.count) {
          return {
            eq: () => ({
              lte: () => ({ count: 0, error: null }),
            }),
          };
        }
        return {
          eq: () => ({
            lte: () => ({
              order: () => ({
                limit: () => ({ data: this.selected, error: null }),
              }),
            }),
          }),
        };
      },
    };
  }
}

function makeSupabase(client: FakeClient) {
  return {
    getClient: () => client,
  } as never;
}

describe("outbox.types", () => {
  it("builds a deterministic, content-derived event id", () => {
    const a = buildDeterministicEventId("username.claimed", "alice");
    const b = buildDeterministicEventId("username.claimed", "alice");
    const c = buildDeterministicEventId("username.claimed", "bob");
    expect(a).toBe(b);
    expect(a).not.toBe(c);
    expect(a).toBe("username.claimed:alice");
  });

  it("createOutboxId returns a unique internal id", () => {
    expect(createOutboxId()).not.toBe(createOutboxId());
  });
});

describe("OutboxRepository", () => {
  let client: FakeClient;
  let repo: OutboxRepository;

  beforeEach(() => {
    client = new FakeClient();
    repo = new OutboxRepository(makeSupabase(client));
  });

  it("stages an event with a pending status and stable shape", async () => {
    const msg = await repo.stage({
      eventId: buildDeterministicEventId("username.claimed", "alice"),
      aggregateType: "username",
      aggregateId: "alice",
      eventType: "username.claimed",
      payload: { username: "alice" },
    });

    expect(msg.status).toBe<OutboxStatus>("pending");
    expect(client.inserted).toHaveLength(1);
    expect(client.inserted[0].event_id).toBe("username.claimed:alice");
    expect(client.inserted[0].status).toBe("pending");
    expect(client.inserted[0].attempts).toBe(0);
  });

  it("marks an event dispatched", async () => {
    await repo.markDispatched("id-1", new Date("2026-01-01T00:00:00Z"));
    expect(client.updated[0]).toMatchObject({
      status: "dispatched",
      dispatched_at: "2026-01-01T00:00:00.000Z",
    });
  });

  it("records a failed attempt and applies backoff delay", async () => {
    await repo.recordAttempt(
      "id-1",
      "boom",
      3,
      false,
      new Date("2026-01-01T00:00:05Z"),
    );
    expect(client.updated[0]).toMatchObject({
      attempts: 3,
      last_error: "boom",
      status: "pending",
      next_attempt_at: "2026-01-01T00:00:05.000Z",
    });
  });

  it("records a dead-letter attempt when retries are exhausted", async () => {
    await repo.recordAttempt(
      "id-1",
      "boom",
      25,
      true,
      new Date("2026-01-01T00:00:05Z"),
    );
    expect(client.updated[0].status).toBe("failed");
  });
});
