import * as crypto from "crypto";

import { WebhooksController } from "./webhooks.controller";
import { WebhookService } from "./webhook.service";

function sign(body: string, timestamp: string, secret: string): string {
  const hmac = crypto.createHmac("sha256", secret);
  hmac.update(`${timestamp}.${body}`);
  return `sha256=${hmac.digest("hex")}`;
}

describe("WebhooksController#verifySignature", () => {
  const controller = new WebhooksController({} as WebhookService);

  it("returns valid: true for a correctly signed payload", () => {
    const payload = JSON.stringify({ eventType: "payment.received" });
    const timestamp = new Date().toISOString();
    const secret = "whsec_test";
    const signature = sign(payload, timestamp, secret);

    const result = controller.verifySignature({ payload, signature, timestamp, secret });

    expect(result).toEqual({ valid: true, reason: "VALID" });
  });

  it("returns a SIGNATURE_MISMATCH reason code for the wrong secret", () => {
    const payload = JSON.stringify({ eventType: "payment.received" });
    const timestamp = new Date().toISOString();
    const signature = sign(payload, timestamp, "wrong-secret");

    const result = controller.verifySignature({
      payload,
      signature,
      timestamp,
      secret: "whsec_test",
    });

    expect(result).toEqual({ valid: false, reason: "SIGNATURE_MISMATCH" });
  });

  it("returns a TIMESTAMP_OUT_OF_TOLERANCE reason code for a stale timestamp", () => {
    const payload = JSON.stringify({ eventType: "payment.received" });
    const secret = "whsec_test";
    const staleTimestamp = new Date(Date.now() - 10 * 60 * 1000).toISOString();
    const signature = sign(payload, staleTimestamp, secret);

    const result = controller.verifySignature({
      payload,
      signature,
      timestamp: staleTimestamp,
      secret,
    });

    expect(result).toEqual({ valid: false, reason: "TIMESTAMP_OUT_OF_TOLERANCE" });
  });
});
