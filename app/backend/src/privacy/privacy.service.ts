import { Injectable, BadRequestException } from "@nestjs/common";
import {
  createCipheriv,
  createDecipheriv,
  createHash,
  diffieHellman,
  generateKeyPairSync,
  KeyObject,
  randomBytes,
  createPrivateKey,
  createPublicKey,
} from "crypto";

export type StealthEnvelope = {
  ephPublicKeyPem: string;
  ivBase64: string;
  authTagBase64: string;
  ciphertextBase64: string;
  algorithm: "aes-256-gcm";
};

@Injectable()
export class PrivacyService {
  encryptRecipientForViewKey(
    recipientAddress: string,
    recipientViewPublicKeyPem: string,
  ): StealthEnvelope {
    if (!recipientAddress || typeof recipientAddress !== "string") {
      throw new BadRequestException("Recipient address is required");
    }
    if (!recipientViewPublicKeyPem || typeof recipientViewPublicKeyPem !== "string") {
      throw new BadRequestException("Recipient view public key is required");
    }

    let recipientKey: KeyObject;
    try {
      recipientKey = createPublicKey(recipientViewPublicKeyPem);
    } catch {
      throw new BadRequestException("Invalid recipient view public key format");
    }

    const { privateKey: ephPrivateKey, publicKey: ephPublicKey } =
      generateKeyPairSync("x25519");

    const shared = diffieHellman({ privateKey: ephPrivateKey, publicKey: recipientKey });
    const encryptionKey = createHash("sha256").update(shared).digest();
    const iv = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", encryptionKey, iv);
    const ciphertext = Buffer.concat([
      cipher.update(recipientAddress, "utf8"),
      cipher.final(),
    ]);
    const authTag = cipher.getAuthTag();

    return {
      ephPublicKeyPem: ephPublicKey.export({ format: "pem", type: "spki" }).toString(),
      ivBase64: iv.toString("base64"),
      authTagBase64: authTag.toString("base64"),
      ciphertextBase64: ciphertext.toString("base64"),
      algorithm: "aes-256-gcm",
    };
  }

  deriveSharedSecretHex(
    privateKeyPem: string,
    publicKeyPem: string,
  ): string {
    if (!privateKeyPem || typeof privateKeyPem !== "string") {
      throw new BadRequestException("Private key is required");
    }
    if (!publicKeyPem || typeof publicKeyPem !== "string") {
      throw new BadRequestException("Public key is required");
    }

    let privateKey: KeyObject;
    let publicKey: KeyObject;
    try {
      privateKey = createPrivateKey(privateKeyPem);
    } catch {
      throw new BadRequestException("Invalid private key format");
    }
    try {
      publicKey = createPublicKey(publicKeyPem);
    } catch {
      throw new BadRequestException("Invalid public key format");
    }

    return diffieHellman({ privateKey, publicKey }).toString("hex");
  }

  decryptRecipientEnvelope(
    envelope: StealthEnvelope,
    recipientViewPrivateKeyPem: string,
  ): string {
    if (!envelope?.ephPublicKeyPem) {
      throw new BadRequestException("Envelope is missing ephemeral public key");
    }
    if (!recipientViewPrivateKeyPem || typeof recipientViewPrivateKeyPem !== "string") {
      throw new BadRequestException("Recipient view private key is required");
    }

    let privateKey: KeyObject;
    try {
      privateKey = createPrivateKey(recipientViewPrivateKeyPem);
    } catch {
      throw new BadRequestException("Invalid recipient view private key format");
    }

    let ephPublic: KeyObject;
    try {
      ephPublic = createPublicKey(envelope.ephPublicKeyPem);
    } catch {
      throw new BadRequestException("Invalid envelope ephemeral public key format");
    }

    let shared: Buffer;
    try {
      shared = diffieHellman({ privateKey, publicKey: ephPublic });
    } catch {
      throw new BadRequestException("Failed to derive shared secret - key mismatch");
    }

    const encryptionKey = createHash("sha256").update(shared).digest();
    const decipher = createDecipheriv(
      "aes-256-gcm",
      encryptionKey,
      Buffer.from(envelope.ivBase64, "base64"),
    );

    try {
      decipher.setAuthTag(Buffer.from(envelope.authTagBase64, "base64"));
    } catch {
      throw new BadRequestException("Invalid authentication tag format");
    }

    let plaintext: Buffer;
    try {
      plaintext = Buffer.concat([
        decipher.update(Buffer.from(envelope.ciphertextBase64, "base64")),
        decipher.final(),
      ]);
    } catch {
      throw new BadRequestException("Decryption failed - data may be tampered or key mismatch");
    }

    return plaintext.toString("utf8");
  }
}