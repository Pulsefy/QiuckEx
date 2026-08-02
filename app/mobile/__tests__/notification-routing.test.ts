import { routeFromNotificationResponse, routeFromPushPayload, parsePushNotificationPayload } from "../services/notification-routing";
import { PUSH_NOTIFICATION_TYPES } from "../types/push-notification";

describe("notification routing payload contracts", () => {
  it("accepts transaction payload contract", () => {
    const payload = parsePushNotificationPayload({
      type: PUSH_NOTIFICATION_TYPES.transactionDetail,
      transactionId: "tx_123",
    });

    expect(payload).toEqual({
      type: PUSH_NOTIFICATION_TYPES.transactionDetail,
      transactionId: "tx_123",
      txHash: undefined,
      amount: undefined,
      asset: undefined,
      status: undefined,
    });
  });

  it("rejects malformed payload", () => {
    const payload = parsePushNotificationPayload({
      type: PUSH_NOTIFICATION_TYPES.escrowDetail,
    });

    expect(payload).toBeNull();
  });

  it("routes listing payload to listing detail route", () => {
    const push = jest.fn();
    routeFromPushPayload(
      { push } as any,
      {
        type: PUSH_NOTIFICATION_TYPES.listingDetail,
        listingId: "listing_01",
      },
    );

    expect(push).toHaveBeenCalledWith({
      pathname: "/listing/[id]",
      params: { id: "listing_01", sellerId: "unknown" },
    });
  });

  it("routes partial transaction payloads to transaction detail with defaults", () => {
    const push = jest.fn();
    routeFromPushPayload(
      { push } as any,
      {
        type: PUSH_NOTIFICATION_TYPES.transactionDetail,
        transactionId: "tx_200",
      },
    );

    expect(push).toHaveBeenCalledWith({
      pathname: "/transaction/[id]",
      params: {
        id: "tx_200",
        txHash: "tx_200",
        amount: "0",
        asset: "XLM",
        status: "Success",
        timestamp: expect.any(String),
        source: "notification",
        destination: "notification",
      },
    });
  });

  it("recovers malformed notification payloads by routing to inbox", () => {
    const push = jest.fn();
    const warnSpy = jest.spyOn(console, 'warn').mockImplementation(() => {});

    routeFromNotificationResponse(
      { push } as any,
      {
        notification: {
          request: {
            content: {
              data: {
                type: "unknown_type",
              },
            },
          },
        },
      } as any,
    );

    expect(push).toHaveBeenCalledWith({
      pathname: "/inbox",
      params: {
        source: "notification_recovery",
        reason: "invalid_payload",
      },
    });
    expect(warnSpy).toHaveBeenCalled();
    warnSpy.mockRestore();
  });
});
