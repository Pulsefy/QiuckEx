import { generateKeyPairSync } from "crypto";
import { PrivacyService } from "./privacy.service";
import { BadRequestException } from "@nestjs/common";

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

  describe("encryptRecipientForViewKey validation", () => {
    it("throws BadRequestException when recipientAddress is empty", () => {
      expect(() => service.encryptRecipientForViewKey("", "public-key"))
        .toThrow(BadRequestException);
    });

    it("throws BadRequestException when recipientAddress is not a string", () => {
      expect(() => service.encryptRecipientForViewKey(null as unknown as string, "public-key"))
        .toThrow(BadRequestException);
    });

    it("throws BadRequestException when recipientViewPublicKeyPem is empty", () => {
      expect(() => service.encryptRecipientForViewKey("address", ""))
        .toThrow(BadRequestException);
    });

    it("throws BadRequestException when recipientViewPublicKeyPem is invalid", () => {
      expect(() => service.encryptRecipientForViewKey("address", "invalid-key"))
        .toThrow(BadRequestException);
    });
  });

  describe("deriveSharedSecretHex validation", () => {
    const { privateKey, publicKey } = generateKeyPairSync("x25519");
    const validPrivatePem = privateKey.export({ format: "pem", type: "pkcs8" }).toString();
    const validPublicPem = publicKey.export({ format: "pem", type: "spki" }).toString();

    it("throws BadRequestException when privateKeyPem is empty", () => {
      expect(() => service.deriveSharedSecretHex("", validPublicPem))
        .toThrow(BadRequestException);
    });

    it("throws BadRequestException when publicKeyPem is empty", () => {
      expect(() => service.deriveSharedSecretHex(validPrivatePem, ""))
        .toThrow(BadRequestException);
    });

    it("throws BadRequestException when privateKeyPem is invalid", () => {
      expect(() => service.deriveSharedSecretHex("invalid-key", validPublicPem))
        .toThrow(BadRequestException);
    });

    it("throws BadRequestException when publicKeyPem is invalid", () => {
      expect(() => service.deriveSharedSecretHex(validPrivatePem, "invalid-key"))
        .toThrow(BadRequestException);
    });
  });

  describe("decryptRecipientEnvelope validation", () => {
    const { privateKey, publicKey } = generateKeyPairSync("x25519");
    const validPrivatePem = privateKey.export({ format: "pem", type: "pkcs8" }).toString();
    const validPublicPem = publicKey.export({ format: "pem", type: "spki" }).toString();

    it("throws BadRequestException when envelope is missing ephPublicKeyPem", () => {
      const invalidEnvelope = {
        ephPublicKeyPem: "",
        ivBase64: "iv",
        authTagBase64: "tag",
        ciphertextBase64: "ct",
        algorithm: "aes-256-gcm" as const,
      };
      expect(() => service.decryptRecipientEnvelope(invalidEnvelope, validPrivatePem))
        .toThrow(BadRequestException);
    });

    it("throws BadRequestException when recipientViewPrivateKeyPem is empty", () => {
      const envelope = service.encryptRecipientForViewKey("address", validPublicPem);
      expect(() => service.decryptRecipientEnvelope(envelope, ""))
        .toThrow(BadRequestException);
    });

    it("throws BadRequestException when recipientViewPrivateKeyPem is invalid", () => {
      const envelope = service.encryptRecipientForViewKey("address", validPublicPem);
      expect(() => service.decryptRecipientEnvelope(envelope, "invalid-key"))
        .toThrow(BadRequestException);
    });

    it("throws BadRequestException when envelope has invalid ephPublicKeyPem", () => {
      const invalidEnvelope = {
        ephPublicKeyPem: "invalid-key",
        ivBase64: "aXZ",
        authTagBase64: "dGVzdA==",
        ciphertextBase64: "dGVzdA==",
        algorithm: "aes-256-gcm" as const,
      };
      expect(() => service.decryptRecipientEnvelope(invalidEnvelope, validPrivatePem))
        .toThrow(BadRequestException);
    });

    it("throws BadRequestException for tampered ciphertext", () => {
      const envelope = service.encryptRecipientForViewKey("address", validPublicPem);
      const tamperedEnvelope = { ...envelope, ciphertextBase64: "tampered" };
      expect(() => service.decryptRecipientEnvelope(tamperedEnvelope, validPrivatePem))
        .toThrow(BadRequestException);
    });
  });
});