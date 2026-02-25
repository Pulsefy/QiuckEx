// src/soroban/soroban-rpc.service.ts
import { Injectable, Logger } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import * as StellarSdk from "@stellar/stellar-sdk";
import { rpc as SorobanRpc } from "@stellar/stellar-sdk";

@Injectable()
export class SorobanRpcService {
  private readonly logger = new Logger(SorobanRpcService.name);
  private readonly rpcUrl: string;

  constructor(private readonly configService: ConfigService) {
    this.rpcUrl = this.configService.get<string>(
      "SOROBAN_RPC_URL",
      "https://soroban-testnet.stellar.org",
    );
  }

  getServer(): SorobanRpc.Server {
    return new SorobanRpc.Server(this.rpcUrl, { allowHttp: false });
  }

  async getAccount(publicKey: string): Promise<StellarSdk.Account> {
    const server = this.getServer();
    try {
      return await server.getAccount(publicKey);
    } catch (err) {
      throw new Error(`account "${publicKey}" does not exist on the network`);
    }
  }

  async simulateTransaction(
    tx: StellarSdk.Transaction,
  ): Promise<SorobanRpc.Api.SimulateTransactionResponse> {
    const server = this.getServer();
    return server.simulateTransaction(tx);
  }

  async getNetworkPassphrase(): Promise<string> {
    const server = this.getServer();
    const network = await server.getNetwork();
    return network.passphrase;
  }
}
