export interface ResourceEstimate {
  cpuInstructions: number;
  memoryBytes: number;
  ledgerReads: number;
  ledgerWrites: number;
  eventBytes: number;
  returnValueBytes: number;
}

export interface FeeEstimate {
  baseFee: string; // in stroops
  inclusionFee: string; // in stroops
  totalFee: string; // in stroops
  totalFeeXLM: string; // human-readable XLM
}

export interface ComposeTransactionResponse {
  success: true;
  unsignedXdr: string;
  resourceEstimate: ResourceEstimate;
  feeEstimate: FeeEstimate;
  minResourceFee: string;
  simulationLatencyMs: number;
}

export interface ComposeTransactionError {
  success: false;
  error: string;
  userMessage: string;
  details?: Record<string, unknown>;
}
