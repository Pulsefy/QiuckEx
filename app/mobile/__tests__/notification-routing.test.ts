import { routeFromPushPayload, parsePushNotificationPayload } from "../services/notification-routing";
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
});
