// src/soroban/soroban-rpc.service.ts
import { Injectable, Logger } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import * as StellarSdk from "@stellar/stellar-sdk";
import { rpc as SorobanRpc } from "@stellar/stellar-sdk";
import { MetricsService } from "../metrics/metrics.service";

@Injectable()
export class SorobanRpcService {
  private readonly logger = new Logger(SorobanRpcService.name);
  private readonly rpcUrls: string[];
  private readonly requestTimeoutMs: number;
  private readonly maxRetries: number;
  private activeIndex = 0;

  constructor(
    private readonly configService: ConfigService,
    private readonly metricsService: MetricsService,
  ) {
    const configuredUrls =
      this.configService.get<string[]>('stellar.sorobanRpcUrls') ?? [];
    const primaryUrl =
      this.configService.get<string>('stellar.sorobanRpcUrl') ??
      'https://soroban-testnet.stellar.org';
    this.rpcUrls = Array.from(new Set([primaryUrl, ...configuredUrls]));

    this.requestTimeoutMs = Number(
      this.configService.get<string>('SOROBAN_RPC_TIMEOUT_MS') ?? 10_000,
    );
    this.maxRetries = Math.max(
      1,
      Number(this.configService.get<string>('SOROBAN_RPC_MAX_RETRIES') ?? 3),
    );

    this.metricsService.setSorobanRpcActiveEndpoint(
      this.rpcUrls[this.activeIndex],
      this.rpcUrls,
    );
    this.logger.log(
      `Soroban RPC initialized with ${this.rpcUrls.length} endpoint(s). Active: ${this.rpcUrls[this.activeIndex]}`,
    );
  }

  private createServer(url: string): SorobanRpc.Server {
    return new SorobanRpc.Server(url, { allowHttp: false });
  }

  private getActiveUrl(): string {
    return this.rpcUrls[this.activeIndex];
  }

  private rotateEndpoint(reason: string): void {
    if (this.rpcUrls.length <= 1) return;
    const previous = this.getActiveUrl();
    this.activeIndex = (this.activeIndex + 1) % this.rpcUrls.length;
    const next = this.getActiveUrl();
    this.metricsService.recordSorobanRpcFailover(previous, next, reason);
    this.metricsService.setSorobanRpcActiveEndpoint(next, this.rpcUrls);
    this.logger.warn(`Soroban RPC failover: ${previous} -> ${next} (${reason})`);
  }

  private isTransientError(error: unknown): boolean {
    const message = String((error as Error)?.message ?? error).toLowerCase();
    return (
      message.includes('timeout') ||
      message.includes('network') ||
      message.includes('fetch') ||
      message.includes('econn') ||
      message.includes('429') ||
      message.includes('503') ||
      message.includes('502') ||
      message.includes('500')
    );
  }

  private async withTimeout<T>(promise: Promise<T>, operation: string): Promise<T> {
    let timeout: NodeJS.Timeout | undefined;
    const timeoutPromise = new Promise<T>((_, reject) => {
      timeout = setTimeout(() => {
        reject(
          new Error(
            `Soroban RPC ${operation} timed out after ${this.requestTimeoutMs}ms`,
          ),
        );
      }, this.requestTimeoutMs);
    });
    try {
      return await Promise.race([promise, timeoutPromise]);
    } finally {
      if (timeout) clearTimeout(timeout);
    }
  }

  private async executeWithFailover<T>(
    operation: string,
    call: (server: SorobanRpc.Server) => Promise<T>,
  ): Promise<T> {
    let lastError: unknown;

    for (let attempt = 1; attempt <= this.maxRetries; attempt += 1) {
      const url = this.getActiveUrl();
      const startedAt = Date.now();
      try {
        const server = this.createServer(url);
        const result = await this.withTimeout(call(server), operation);
        this.metricsService.recordExternalCall(
          'soroban_rpc',
          `${operation}:${url}`,
          (Date.now() - startedAt) / 1000,
        );
        return result;
      } catch (error) {
        lastError = error;
        this.metricsService.recordError(
          'soroban_rpc',
          this.isTransientError(error) ? 'transient' : 'non_transient',
        );
        if (!this.isTransientError(error) || attempt >= this.maxRetries) {
          break;
        }

        const backoffMs = Math.min(
          250 * 2 ** (attempt - 1) + Math.floor(Math.random() * 200),
          3000,
        );
        this.rotateEndpoint((error as Error).message ?? 'transient-error');
        await new Promise((resolve) => setTimeout(resolve, backoffMs));
      }
    }

    throw lastError instanceof Error
      ? lastError
      : new Error(`Soroban RPC ${operation} failed`);
  }

  async getAccount(publicKey: string): Promise<StellarSdk.Account> {
    try {
      return await this.executeWithFailover("getAccount", (server) =>
        server.getAccount(publicKey),
      );
    } catch (err) {
      throw new Error(`account "${publicKey}" does not exist on the network`);
    }
  }

  async simulateTransaction(
    tx: StellarSdk.Transaction,
  ): Promise<SorobanRpc.Api.SimulateTransactionResponse> {
    return this.executeWithFailover("simulateTransaction", (server) =>
      server.simulateTransaction(tx),
    );
  }

  async getNetworkPassphrase(): Promise<string> {
    const network = await this.executeWithFailover("getNetwork", (server) =>
      server.getNetwork(),
    );
    return network.passphrase;
  }
}
