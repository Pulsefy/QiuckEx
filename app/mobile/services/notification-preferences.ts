import { Keypair } from "stellar-sdk";

export interface NotificationPreferenceDto {
  id?: string;
  publicKey: string;
  channel: "email" | "push" | "webhook" | "telegram";
  email?: string;
  pushToken?: string;
  webhookUrl?: string;
  webhookSecret?: string;
  events?: string[] | null;
  minAmountStroops?: string | number;
  enabled: boolean;
}

export interface WalletSigner {
  publicKey: string;
  sign: (data: Buffer) => Buffer;
}

/**
 * Creates authentication headers (x-signature and x-timestamp) for requests to
 * protected backend notification endpoints using a Stellar Keypair or Signer identity.
 */
export function createSignatureHeaders(
  method: string,
  path: string,
  signer: WalletSigner,
  timestampMs: number = Date.now(),
): {
  "x-signature": string;
  "x-timestamp": string;
  "x-public-key": string;
} {
  const timestampStr = timestampMs.toString();
  const payload = `${method.toUpperCase()}:${path}:${timestampStr}`;
  const signatureBuffer = signer.sign(Buffer.from(payload));
  const signatureBase64 = signatureBuffer.toString("base64");

  return {
    "x-signature": signatureBase64,
    "x-timestamp": timestampStr,
    "x-public-key": signer.publicKey,
  };
}

/**
 * Helper to update notification preferences on backend with wallet signature auth.
 */
export async function registerNotificationPreference(
  baseUrl: string,
  signer: WalletSigner,
  dto: Omit<NotificationPreferenceDto, "publicKey">,
): Promise<NotificationPreferenceDto> {
  const path = `/notifications/preferences/${signer.publicKey}`;
  const url = `${baseUrl.replace(/\/$/, "")}${path}`;
  const headers = {
    "Content-Type": "application/json",
    ...createSignatureHeaders("PUT", path, signer),
  };

  const response = await fetch(url, {
    method: "PUT",
    headers,
    body: JSON.stringify(dto),
  });

  if (!response.ok) {
    throw new Error(`Failed to update notification preference: ${response.status} ${response.statusText}`);
  }

  return response.json();
}
