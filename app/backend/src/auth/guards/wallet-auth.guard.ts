import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
  Optional,
  UnauthorizedException,
} from "@nestjs/common";
import { Keypair } from "@stellar/stellar-sdk";
import { ApiKeysService } from "../../api-keys/api-keys.service";

@Injectable()
export class WalletAuthGuard implements CanActivate {
  constructor(
    @Optional() private readonly apiKeysService?: ApiKeysService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest();
    const paramPublicKey: string | undefined = request.params?.publicKey;

    if (!paramPublicKey) {
      // If endpoint doesn't have a publicKey parameter, allow
      return true;
    }

    // Read signature headers
    const rawSignature =
      (request.headers["x-signature"] as string) ||
      (request.headers["x-wallet-signature"] as string);
    const rawTimestamp =
      (request.headers["x-timestamp"] as string) ||
      (request.headers["x-signature-timestamp"] as string);
    const headerPublicKey = request.headers["x-public-key"] as string | undefined;

    // Read API key header
    const rawApiKey = request.headers["x-api-key"] as string | undefined;

    // 1. Signature-based authentication check
    if (rawSignature && rawTimestamp) {
      return this.verifySignatureAuth(
        request,
        paramPublicKey,
        rawSignature,
        rawTimestamp,
        headerPublicKey,
      );
    }

    // 2. API Key authentication check
    if (rawApiKey && this.apiKeysService) {
      return this.verifyApiKeyAuth(request, paramPublicKey, rawApiKey);
    }

    // 3. Reject unauthenticated requests
    throw new UnauthorizedException({
      error: "UNAUTHORIZED",
      message:
        "Authentication proof required. Provide x-signature & x-timestamp headers or a valid x-api-key.",
    });
  }

  private verifySignatureAuth(
    request: any,
    paramPublicKey: string,
    rawSignature: string,
    rawTimestamp: string,
    headerPublicKey?: string,
  ): boolean {
    // Check timestamp freshness (5 minutes replay window)
    const timestampMs = this.parseTimestamp(rawTimestamp);
    if (!timestampMs || Math.abs(Date.now() - timestampMs) > 5 * 60 * 1000) {
      throw new UnauthorizedException({
        error: "EXPIRED_TIMESTAMP",
        message: "Signature timestamp is invalid or expired (must be within 5 minutes)",
      });
    }

    // Cross-wallet check if header public key is provided and differs
    if (headerPublicKey && headerPublicKey !== paramPublicKey) {
      const isHeaderKeyValid = this.verifyStellarSignature(
        headerPublicKey,
        request,
        rawTimestamp,
        rawSignature,
      );
      if (isHeaderKeyValid) {
        throw new ForbiddenException({
          error: "FORBIDDEN_CROSS_WALLET",
          message: "Authenticated wallet identity is forbidden from accessing target wallet resource",
        });
      }
    }

    // Verify signature against target paramPublicKey
    const isValid = this.verifyStellarSignature(
      paramPublicKey,
      request,
      rawTimestamp,
      rawSignature,
    );

    if (!isValid) {
      throw new UnauthorizedException({
        error: "INVALID_SIGNATURE",
        message: "Signature verification failed for the target public key",
      });
    }

    request.walletAddress = paramPublicKey;
    return true;
  }

  private verifyStellarSignature(
    publicKey: string,
    request: any,
    timestamp: string,
    signature: string,
  ): boolean {
    try {
      const keypair = Keypair.fromPublicKey(publicKey);
      const signatureBuf = this.parseSignatureBuffer(signature);
      if (!signatureBuf) return false;

      // Primary payload standard: METHOD:PATH:TIMESTAMP
      const method = (request.method || "GET").toUpperCase();
      const path = request.originalUrl || request.url || "";
      const primaryPayload = `${method}:${path}:${timestamp}`;

      if (keypair.verify(Buffer.from(primaryPayload), signatureBuf)) {
        return true;
      }

      // Secondary payload fallback: PUBLIC_KEY:TIMESTAMP
      const secondaryPayload = `${publicKey}:${timestamp}`;
      if (keypair.verify(Buffer.from(secondaryPayload), signatureBuf)) {
        return true;
      }

      return false;
    } catch {
      return false;
    }
  }

  private parseSignatureBuffer(signature: string): Buffer | null {
    try {
      const b64Buf = Buffer.from(signature, "base64");
      if (b64Buf.toString("base64") === signature) {
        return b64Buf;
      }
      if (/^[0-9a-fA-F]+$/.test(signature)) {
        return Buffer.from(signature, "hex");
      }
      return Buffer.from(signature, "utf8");
    } catch {
      return null;
    }
  }

  private parseTimestamp(rawTimestamp: string): number | null {
    if (/^\d+$/.test(rawTimestamp)) {
      const num = parseInt(rawTimestamp, 10);
      return num < 1e11 ? num * 1000 : num;
    }
    const parsed = Date.parse(rawTimestamp);
    return isNaN(parsed) ? null : parsed;
  }

  private async verifyApiKeyAuth(
    request: any,
    paramPublicKey: string,
    rawApiKey: string,
  ): Promise<boolean> {
    const result = await this.apiKeysService!.validateKey(rawApiKey);
    if (!result) {
      throw new UnauthorizedException({
        error: "INVALID_API_KEY",
        message: "API key is invalid",
      });
    }

    const { record } = result;
    const keyBoundWallet = (record as any).wallet_address || (record as any).publicKey;
    if (keyBoundWallet && keyBoundWallet !== paramPublicKey) {
      throw new ForbiddenException({
        error: "FORBIDDEN_CROSS_WALLET",
        message: "API key is not scoped to target wallet address",
      });
    }

    request.apiKey = record;
    request.walletAddress = paramPublicKey;
    return true;
  }
}
