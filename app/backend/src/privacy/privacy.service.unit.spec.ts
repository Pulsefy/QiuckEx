import { generateKeyPairSync } from "crypto";
import { PrivacyService } from "./privacy.service";

describe("PrivacyService", () => {
  const service = new PrivacyService();

  it("encrypts and decrypts recipient metadata with recipient view key", () => {
    const { privateKey, publicKey } = generateKeyPairSync("x25519");
    const recipientAddress = "GDSTESTRECIPIENTADDRESS00000000000000000000000000000000000";
    const recipientPublicPem = publicKey
      .export({ format: "pem", type: "spki" })
      .toString();
    const recipientPrivatePem = privateKey
      .export({ format: "pem", type: "pkcs8" })
      .toString();

    const envelope = service.encryptRecipientForViewKey(
      recipientAddress,
      recipientPublicPem,
    );
    const decrypted = service.decryptRecipientEnvelope(
      envelope,
      recipientPrivatePem,
    );

    expect(decrypted).toBe(recipientAddress);
  });

  it("derives matching shared secret from counterpart key pairs", () => {
    const alice = generateKeyPairSync("x25519");
    const bob = generateKeyPairSync("x25519");

    const aliceSecret = service.deriveSharedSecretHex(
      alice.privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
      bob.publicKey.export({ format: "pem", type: "spki" }).toString(),
    );
    const bobSecret = service.deriveSharedSecretHex(
      bob.privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
      alice.publicKey.export({ format: "pem", type: "spki" }).toString(),
    );

    expect(aliceSecret).toBe(bobSecret);
  });
});
