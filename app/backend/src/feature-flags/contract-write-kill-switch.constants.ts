import { SorobanErrorCode } from '../common/soroban-errors';

export const TESTNET_CONTRACT_WRITES_FLAG = 'testnet.contract_writes';

export const CONTRACT_WRITES_DISABLED_CODE =
  SorobanErrorCode.CONTRACT_WRITES_DISABLED;

export const CONTRACT_WRITES_DISABLED_MESSAGE =
  'Contract write operations are temporarily disabled on testnet. Retry after the incident is resolved or consult the status page.';
