import {
  Injectable,
  Logger,
  BadRequestException,
  InternalServerErrorException,
} from "@nestjs/common";
import { createHash } from "crypto";
import * as StellarSdk from "@stellar/stellar-sdk";
import { rpc as SorobanRpc } from "@stellar/stellar-sdk";
import { ComposeTransactionDto, SimulateOperationDto, SubmitSignedTransactionDto } from "./dto/compose-transaction.dto";
import {
  ComposeTransactionResponse,
  ComposeTransactionError,
  ResourceEstimate,
  FeeEstimate,
} from "./dto/compose-transaction-response.dto";
import { buildScVal } from "./utils/param-builder";
import { SorobanRpcService } from "./soroban-rpc.service";
import { mapSorobanError } from "../common/soroban-errors";
import { SorobanErrorCode } from "../common/soroban-errors";

type BuildAndSimulateResult =
  | {
      success: true;
      tx: StellarSdk.Transaction;
      simulationResult: SorobanRpc.Api.SimulateTransactionResponse;
      resourceEstimate: ResourceEstimate;
      minResourceFee: string;
      simulationLatencyMs: number;
    }
  | {
      success: false;
      error: string;
      userMessage: string;
      details?: Record<string, unknown>;
      simulationLatencyMs: number;
    };

function isSimulationSuccessResult(
  result: BuildAndSimulateResult,
): result is Extract<BuildAndSimulateResult, { success: true }> {
  return result.success === true;
}

const STROOPS_PER_XLM = 10_000_000;
const BASE_FEE = 100; // stroops

@Injectable()
export class TransactionsService {
  private readonly logger = new Logger(TransactionsService.name);
  private readonly idempotencyResponses = new Map<
    string,
    ComposeTransactionResponse | ComposeTransactionError
  >();
  private readonly idempotencyFingerprints = new Map<string, string>();
  private readonly submitIdempotencyResponses = new Map<
    string,
    { success: boolean; hash?: string; error?: string; userMessage?: string }
  >();
  private readonly submitIdempotencyFingerprints = new Map<string, string>();

  constructor(private readonly sorobanRpcService: SorobanRpcService) {}

  async composeTransaction(
    dto: ComposeTransactionDto,
  ): Promise<ComposeTransactionResponse | ComposeTransactionError> {
    this.validatePayload(dto);

    const payloadFingerprint = this.buildFingerprint(dto);
    const idempotencyKey = dto.idempotencyKey ?? payloadFingerprint;
    const fingerprintForKey = this.idempotencyFingerprints.get(idempotencyKey);
    if (fingerprintForKey && fingerprintForKey !== payloadFingerprint) {
      throw new BadRequestException(
        "This idempotency key was already used with a different payload.",
      );
    }

    const cached = this.idempotencyResponses.get(idempotencyKey);
    if (cached) {
      return cached;
    }

    const sim = await this.buildAndSimulateTransaction(dto);
    if (!isSimulationSuccessResult(sim)) {
      const failedResponse: ComposeTransactionError = {
        success: false,
        error: sim.error,
        userMessage: sim.userMessage,
        details: sim.details,
      };
      this.rememberResponse(idempotencyKey, payloadFingerprint, failedResponse);
      return failedResponse;
    }

    // 9. Assemble transaction with simulation results (sets soroban data & resource fee)
    const assembledTx = SorobanRpc.assembleTransaction(
      sim.tx,
      sim.simulationResult,
    ).build();

    const resourceEstimate = sim.resourceEstimate;

    // 11. Fee breakdown
    const minResourceFee = sim.minResourceFee;
    const totalFeeStroops = BASE_FEE + Number(minResourceFee);

    const feeEstimate: FeeEstimate = {
      baseFee: String(BASE_FEE),
      inclusionFee: minResourceFee,
      totalFee: String(totalFeeStroops),
      totalFeeXLM: (totalFeeStroops / STROOPS_PER_XLM).toFixed(7),
    };

    // 12. Return unsigned XDR
    const unsignedXdr = assembledTx.toEnvelope().toXDR("base64");

    this.logger.log(
      `Transaction composed successfully in ${sim.simulationLatencyMs}ms — ` +
        `${dto.contractId}::${dto.method}, fee: ${totalFeeStroops} stroops`,
    );

    const txDataAny = (
      sim.simulationResult as unknown as {
        transactionData?: { build?: () => any } | any;
      }
    ).transactionData;
    const sorobanData =
      typeof txDataAny?.build === "function" ? txDataAny.build() : txDataAny;
    const resources =
      sorobanData && typeof sorobanData.resources === "function"
        ? sorobanData.resources()
        : undefined;

    const response: ComposeTransactionResponse = {
      success: true,
      unsignedXdr,
      resourceEstimate,
      feeEstimate,
      minResourceFee,
      simulationLatencyMs: sim.simulationLatencyMs,
      idempotencyKey,
      simulationSummary: {
        status: "success" as const,
        footprint: {
          readOnly: resources ? resources.footprint().readOnly().length : 0,
          readWrite: resources ? resources.footprint().readWrite().length : 0,
        },
        estimatedCost: {
          cpuInstructions: resourceEstimate.cpuInstructions,
          ledgerReads: resourceEstimate.ledgerReads,
          ledgerWrites: resourceEstimate.ledgerWrites,
          eventBytes: resourceEstimate.eventBytes,
          returnValueBytes: resourceEstimate.returnValueBytes,
        },
      },
    };
    this.rememberResponse(idempotencyKey, payloadFingerprint, response);
    return response;
  }

  async simulateOperation(
    dto: SimulateOperationDto,
  ): Promise<{
    success: boolean;
    error?: string;
    userMessage?: string;
    details?: Record<string, unknown>;
  }> {
    const sim = await this.buildAndSimulateTransaction(dto);
    if (!isSimulationSuccessResult(sim)) {
      return {
        success: false,
        error: sim.error,
        userMessage: sim.userMessage,
        details: sim.details,
      };
    }

    return {
      success: true,
      details: {
        cpuInstructions: sim.resourceEstimate.cpuInstructions,
        memoryBytes: sim.resourceEstimate.memoryBytes,
        ledgerReads: sim.resourceEstimate.ledgerReads,
        ledgerWrites: sim.resourceEstimate.ledgerWrites,
        eventBytes: sim.resourceEstimate.eventBytes,
        ...(sim.resourceEstimate.returnValueBytes !== undefined
          ? { returnValueBytes: sim.resourceEstimate.returnValueBytes }
          : {}),
        ...(sim.minResourceFee !== undefined
          ? { minResourceFee: sim.minResourceFee }
          : {}),
      },
    };
  }

  private async buildAndSimulateTransaction(dto: {
    contractId: string;
    method: string;
    params: ComposeTransactionDto["params"];
    sourceAccount: string;
    networkPassphrase?: string;
    memo?: ComposeTransactionDto["memo"];
  }): Promise<BuildAndSimulateResult> {
    this.validatePayload(dto);

    const startTime = Date.now();

    // 1. Resolve network passphrase
    const networkPassphrase =
      dto.networkPassphrase ??
      (await this.sorobanRpcService.getNetworkPassphrase());

    // 2. Load source account from network (gets current sequence number)
    let account: StellarSdk.Account;
    try {
      account = await this.sorobanRpcService.getAccount(dto.sourceAccount);
    } catch (err) {
      return {
        success: false,
        error: err.message,
        userMessage: `Source account not found: ${err.message}`,
        simulationLatencyMs: Date.now() - startTime,
      };
    }

    // 3. Build ScVal params
    let scParams: StellarSdk.xdr.ScVal[];
    try {
      scParams = dto.params.map(buildScVal);
    } catch (err) {
      throw new BadRequestException(`Invalid parameter: ${err.message}`);
    }

    // 4. Build the contract invocation operation
    const contract = new StellarSdk.Contract(dto.contractId);
    const operation = contract.call(dto.method, ...scParams);

    // 5. Build transaction envelope (no private key — unsigned)
    const txBuilder = new StellarSdk.TransactionBuilder(account, {
      fee: String(BASE_FEE),
      networkPassphrase,
    })
      .addOperation(operation)
      .setTimeout(StellarSdk.TimeoutInfinite);

    // Add canonical memo if provided
    if (dto.memo) {
      switch (dto.memo.type) {
        case "text":
          txBuilder.addMemo(StellarSdk.Memo.text(dto.memo.value));
          break;
        case "id":
          txBuilder.addMemo(StellarSdk.Memo.id(dto.memo.value));
          break;
        case "hash":
          txBuilder.addMemo(
            StellarSdk.Memo.hash(
              Buffer.from(dto.memo.value, "hex").toString("base64"),
            ),
          );
          break;
        case "return":
          txBuilder.addMemo(
            StellarSdk.Memo.return(
              Buffer.from(dto.memo.value, "hex").toString("base64"),
            ),
          );
          break;
      }
    }

    const tx = txBuilder.build();

    // 6. Simulate (preflight)
    this.logger.debug(
      `Simulating transaction: ${dto.contractId}::${dto.method}`,
    );

    let simulationResult: SorobanRpc.Api.SimulateTransactionResponse;
    try {
      simulationResult = await this.sorobanRpcService.simulateTransaction(tx);
    } catch (err) {
      this.logger.error("RPC simulation request failed", err);
      throw new InternalServerErrorException(
        "Failed to reach Soroban RPC provider.",
      );
    }

    const simulationLatencyMs = Date.now() - startTime;

    // 7. Handle simulation failure
    if (SorobanRpc.Api.isSimulationError(simulationResult)) {
      const mapped = mapSorobanError(simulationResult.error);
      this.logger.warn(
        `Simulation failed [${mapped.code}]: ${simulationResult.error}`,
      );
      return {
        success: false,
        error: mapped.code,
        userMessage: mapped.message,
        details: mapped.details,
        simulationLatencyMs,
      };
    }

    // 8. Handle restoration needed
    if (SorobanRpc.Api.isSimulationRestore(simulationResult)) {
      return {
        success: false,
        error: SorobanErrorCode.RESTORE_REQUIRED,
        userMessage:
          "Some contract state entries have expired and must be restored before this transaction can proceed. Please run a restore operation first.",
        details: {
          restorePreamble: simulationResult.restorePreamble,
        },
        simulationLatencyMs,
      };
    }

    // Extract resource estimates
    const resourceEstimate = this.extractResourceEstimate(simulationResult);
    const minResourceFee =
      (simulationResult as unknown as { minResourceFee?: string })
        .minResourceFee ?? "0";

    return {
      success: true,
      tx,
      simulationResult,
      resourceEstimate,
      minResourceFee,
      simulationLatencyMs,
    };
  }

  private extractResourceEstimate(
    simulationResult: SorobanRpc.Api.SimulateTransactionResponse,
  ): ResourceEstimate {
    const txDataAny = (
      simulationResult as unknown as {
        transactionData?: { build?: () => any } | any;
      }
    ).transactionData;
    const sorobanData =
      typeof txDataAny?.build === "function" ? txDataAny.build() : txDataAny;
    const resources =
      sorobanData && typeof sorobanData.resources === "function"
        ? sorobanData.resources()
        : undefined;

    const readOnlyLength =
      resources && typeof resources.footprint === "function"
        ? resources.footprint().readOnly().length
        : 0;
    const readWriteLength =
      resources && typeof resources.footprint === "function"
        ? resources.footprint().readWrite().length
        : 0;

    return {
      cpuInstructions:
        resources && typeof resources.instructions === "function"
          ? Number(resources.instructions())
          : 0,
      memoryBytes: 0, // not exposed by Soroban RPC simulate response
      ledgerReads: readOnlyLength + readWriteLength,
      ledgerWrites: readWriteLength,
      eventBytes:
        resources && typeof resources.writeBytes === "function"
          ? Number(resources.writeBytes() ?? 0)
          : 0,
      returnValueBytes: (
        simulationResult as unknown as {
          result?: { retval?: { toXDR: () => string | Buffer } };
        }
      ).result?.retval
        ? (
            simulationResult as unknown as {
              result?: { retval?: { toXDR: () => string | Buffer } };
            }
          ).result!.retval!.toXDR().length
        : 0,
    };
  }

  async submitSignedTransaction(
    dto: SubmitSignedTransactionDto,
  ): Promise<{ success: boolean; hash?: string; error?: string; userMessage?: string }> {
    // Validate the signed XDR is properly formatted (never extracts private keys)
    try {
      // Just validate the XDR can be parsed - we don't need to use the transaction object
      new StellarSdk.Transaction(StellarSdk.xdr.TransactionEnvelope.fromXDR(dto.signedXdr, 'base64'), dto.networkPassphrase || 'Test SDF Network ; September 2015');
    } catch (err) {
      throw new BadRequestException('Invalid signed transaction XDR format');
    }

    // Create fingerprint for idempotency checking
    const payloadFingerprint = createHash('sha256').update(JSON.stringify({
      signedXdr: dto.signedXdr,
      networkPassphrase: dto.networkPassphrase
    })).digest('hex');

    const idempotencyKey = dto.idempotencyKey;
    const fingerprintForKey = this.submitIdempotencyFingerprints.get(idempotencyKey);
    
    if (fingerprintForKey && fingerprintForKey !== payloadFingerprint) {
      throw new BadRequestException(
        'This idempotency key was already used with a different payload.',
      );
    }

    // Return cached response if already processed this idempotency key
    const cached = this.submitIdempotencyResponses.get(idempotencyKey);
    if (cached) {
      return cached;
    }

    // Submit to network (in production would send to Soroban RPC)
    // For now, we simulate submission with 90% success rate (deterministic)
    const txHash = createHash('sha256').update(dto.signedXdr).digest('hex');
    const successDeterminant = parseInt(txHash.substring(0, 2), 16);
    const isSuccess = successDeterminant < 230; // 230/256 = ~90% success rate
    
    let response;
    if (isSuccess) {
      response = {
        success: true,
        hash: txHash
      };
    } else {
      response = {
        success: false,
        error: 'NETWORK_ERROR',
        userMessage: 'Transaction submission failed due to network conditions. Please retry with the same idempotency key.'
      };
    }

    // Store for idempotency
    this.submitIdempotencyFingerprints.set(idempotencyKey, payloadFingerprint);
    this.submitIdempotencyResponses.set(idempotencyKey, response);
    
    return response;
  }

  private validatePayload(
    dto: ComposeTransactionDto | SimulateOperationDto,
  ): void {
    const payloadSize = Buffer.byteLength(JSON.stringify(dto.params ?? []), "utf8");
    if (payloadSize > 4096) {
      throw new BadRequestException("Transaction parameters exceed the 4KB limit.");
    }

    if ((dto.params ?? []).length > 16) {
      throw new BadRequestException("A maximum of 16 contract parameters is supported.");
    }
  }

  private buildFingerprint(dto: ComposeTransactionDto): string {
    const normalized = JSON.stringify({
      contractId: dto.contractId,
      method: dto.method,
      params: dto.params,
      sourceAccount: dto.sourceAccount,
      networkPassphrase: dto.networkPassphrase ?? "__default__",
    });

    return createHash("sha256").update(normalized).digest("hex");
  }

  private rememberResponse(
    idempotencyKey: string,
    fingerprint: string,
    response: ComposeTransactionResponse | ComposeTransactionError,
  ): void {
    this.idempotencyFingerprints.set(idempotencyKey, fingerprint);
    this.idempotencyResponses.set(idempotencyKey, response);
  }
}