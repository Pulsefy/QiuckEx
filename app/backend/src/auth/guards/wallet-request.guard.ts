import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from "@nestjs/common";
import type { Request } from "express";
import { WalletRequestAuthService } from "../wallet-request-auth.service";

@Injectable()
export class WalletRequestGuard implements CanActivate {
  constructor(private readonly proofs: WalletRequestAuthService) {}

  canActivate(context: ExecutionContext): boolean {
    const request = context.switchToHttp().getRequest<Request>();
    const publicKey = request.headers["x-wallet-public-key"];
    const challenge = request.headers["x-wallet-challenge"];
    const signature = request.headers["x-wallet-signature"];
    if (
      typeof publicKey !== "string" ||
      typeof challenge !== "string" ||
      typeof signature !== "string"
    )
      throw new UnauthorizedException({
        code: "WALLET_PROOF_REQUIRED",
        message: "Wallet ownership proof is required",
      });
    this.proofs.authorize({
      publicKey,
      challenge,
      signature,
      targetPublicKey: request.params.publicKey,
      method: request.method,
      path: request.originalUrl.split("?")[0],
      body: request.method === "PUT" ? request.body : null,
    });
    request.user = { publicKey };
    return true;
  }
}
