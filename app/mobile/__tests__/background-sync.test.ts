import {
  DEFAULT_SYNC_SNAPSHOT,
  mergeSyncSnapshot,
} from "../services/background-sync";

const ACCOUNT_ID =
  "GAMOSFOKEYHFDGMXIEFEYBUYK3ZMFYN3PFLOTBRXFGBFGRKBKLQSLGLP";

describe("mergeSyncSnapshot", () => {
  it("marks first sync items as read to avoid badge floods", () => {
    const snapshot = mergeSyncSnapshot(DEFAULT_SYNC_SNAPSHOT, [
      {
        amount: "10.0000000",
        asset: "XLM",
        memo: "Initial sync",
        timestamp: "2026-04-23T10:00:00Z",
        txHash: "tx-1",
        pagingToken: "1",
        source: "GSOURCE",
        destination: ACCOUNT_ID,
        status: "Success",
      },
    ], ACCOUNT_ID);

    expect(snapshot.notifications[0].read).toBe(true);
    expect(snapshot.initialSyncCompleted).toBe(true);
  });

  it("adds later sync items as unread and keeps newest first", () => {
    const initial = mergeSyncSnapshot(DEFAULT_SYNC_SNAPSHOT, [
      {
        amount: "10.0000000",
        asset: "XLM",
        memo: "Initial sync",
        timestamp: "2026-04-23T10:00:00Z",
        txHash: "tx-1",
        pagingToken: "1",
        source: "GSOURCE",
        destination: ACCOUNT_ID,
        status: "Success",
      },
    ], ACCOUNT_ID);

    const next = mergeSyncSnapshot(initial, [
      {
        amount: "20.0000000",
        asset: "USDC:ISSUER",
        memo: "Fresh payment",
        timestamp: "2026-04-23T11:00:00Z",
        txHash: "tx-2",
        pagingToken: "2",
        source: "GNEWSOURCE",
        destination: ACCOUNT_ID,
        status: "Success",
      },
    ], ACCOUNT_ID);

    expect(next.notifications[0].id).toBe("tx-2");
    expect(next.notifications[0].read).toBe(false);
    expect(next.notifications).toHaveLength(2);
  });
});
