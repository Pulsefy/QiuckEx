import { Injectable } from "@nestjs/common";
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
    const { privateKey: ephPrivateKey, publicKey: ephPublicKey } =
      generateKeyPairSync("x25519");
    const recipientKey = createPublicKey(recipientViewPublicKeyPem);
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
    const privateKey: KeyObject = createPrivateKey(privateKeyPem);
    const publicKey: KeyObject = createPublicKey(publicKeyPem);
    return diffieHellman({ privateKey, publicKey }).toString("hex");
  }

  decryptRecipientEnvelope(
    envelope: StealthEnvelope,
    recipientViewPrivateKeyPem: string,
  ): string {
    const privateKey = createPrivateKey(recipientViewPrivateKeyPem);
    const ephPublic = createPublicKey(envelope.ephPublicKeyPem);
    const shared = diffieHellman({ privateKey, publicKey: ephPublic });
    const encryptionKey = createHash("sha256").update(shared).digest();
    const decipher = createDecipheriv(
      "aes-256-gcm",
      encryptionKey,
      Buffer.from(envelope.ivBase64, "base64"),
    );
    decipher.setAuthTag(Buffer.from(envelope.authTagBase64, "base64"));
    const plaintext = Buffer.concat([
      decipher.update(Buffer.from(envelope.ciphertextBase64, "base64")),
      decipher.final(),
    ]);
    return plaintext.toString("utf8");
  }
}
