/**
 * Canonical contract error codes matching the quickex Soroban contract errors.rs
 */
export enum QuickexErrorCode {
  // Validation failures (100-199)
  InvalidAmount = 100,
  InvalidSalt = 101,
  InvalidPrivacyLevel = 102,

  // Auth/admin failures (200-299)
  Unauthorized = 200,
  AlreadyInitialized = 201,
  InsufficientRole = 202,

  // State, escrow, and commitment violations (300-399)
  ContractPaused = 300,
  PrivacyAlreadySet = 301,
  CommitmentNotFound = 302,
  CommitmentAlreadyExists = 303,
  AlreadySpent = 304,
  InvalidCommitment = 305,
  CommitmentMismatch = 306,
  EscrowExpired = 307,
  EscrowNotExpired = 308,
  InvalidOwner = 309,
  NoArbiter = 310,
  InvalidDisputeState = 311,
  NotArbiter = 312,
  OperationPaused = 313,
  InvalidContractVersion = 314,
  Overpayment = 315,
  ReentrancyDetected = 316,
  HookAlreadyRegistered = 317,
  HookNotRegistered = 318,
  NotAnArbiter = 319,
  ArbiterAlreadyVoted = 320,
  InsufficientVotes = 321,

  // Stealth address errors (400-499)
  StealthAddressMismatch = 400,
  StealthAddressAlreadyUsed = 401,
  StealthEscrowNotFound = 402,

  // Replay protection (500-599)
  NonceAlreadyUsed = 500,
  SignatureExpired = 501,

  // Internal/unexpected conditions (900-999)
  InternalError = 900,
  InvalidTimeout = 901,
}

export interface MappedContractError {
  code: number | string;
  title: string;
  message: string;
  recoveryGuidance: string;
  actionLabel?: string;
  actionType: 'retry' | 'contact_support' | 'check_network' | 'refresh_balance' | 'dismiss' | 'go_back';
}

// Map each code to friendly copy and recovery paths.
const ERROR_MAPPINGS: Record<number, Omit<MappedContractError, 'code'>> = {
  [QuickexErrorCode.InvalidAmount]: {
    title: 'Invalid Payment Amount',
    message: 'The requested transaction amount is invalid, zero, or negative.',
    recoveryGuidance: 'Please specify a positive amount and try again.',
    actionLabel: 'Adjust Amount',
    actionType: 'dismiss',
  },
  [QuickexErrorCode.InvalidSalt]: {
    title: 'Security Validation Failed',
    message: 'The transaction parameter salt is invalid or has been tampered with.',
    recoveryGuidance: 'Regenerate the payment link or QR code and scan again.',
    actionLabel: 'Go Back',
    actionType: 'go_back',
  },
  [QuickexErrorCode.InvalidPrivacyLevel]: {
    title: 'Privacy Option Error',
    message: 'The requested X-Ray privacy setting is invalid or unsupported for this transaction.',
    recoveryGuidance: 'Disable X-Ray privacy or check your network settings and try again.',
    actionLabel: 'Adjust Privacy Settings',
    actionType: 'dismiss',
  },
  [QuickexErrorCode.Unauthorized]: {
    title: 'Access Denied',
    message: 'Your current wallet address is not authorized to perform this contract action.',
    recoveryGuidance: 'Verify you are connected to the correct wallet account in your Stellar app.',
    actionLabel: 'Switch Wallet',
    actionType: 'dismiss',
  },
  [QuickexErrorCode.AlreadyInitialized]: {
    title: 'Contract Already Configured',
    message: 'The smart contract setup operation cannot be repeated.',
    recoveryGuidance: 'No action is needed as the contract is already initialized.',
    actionLabel: 'Dismiss',
    actionType: 'dismiss',
  },
  [QuickexErrorCode.InsufficientRole]: {
    title: 'Administrative Access Required',
    message: 'This operation requires administrator privileges.',
    recoveryGuidance: 'Please switch to an admin/owner account to continue.',
    actionLabel: 'Switch Wallet',
    actionType: 'dismiss',
  },
  [QuickexErrorCode.ContractPaused]: {
    title: 'Service Temporarily Paused',
    message: 'All contract-based transactions are currently paused for system upgrades.',
    recoveryGuidance: 'Please try again in a few minutes. Check official channels for status updates.',
    actionLabel: 'Check Network Status',
    actionType: 'check_network',
  },
  [QuickexErrorCode.PrivacyAlreadySet]: {
    title: 'Privacy Already Set',
    message: 'The privacy configuration has already been applied to this contract transaction.',
    recoveryGuidance: 'No further action is required.',
    actionLabel: 'Dismiss',
    actionType: 'dismiss',
  },
  [QuickexErrorCode.CommitmentNotFound]: {
    title: 'Escrow Commitment Not Found',
    message: 'The secure commitment code for this payment could not be found on-chain.',
    recoveryGuidance: 'Wait a few seconds for the block to finalize, or verify the payment link.',
    actionLabel: 'Refresh Details',
    actionType: 'refresh_balance',
  },
  [QuickexErrorCode.CommitmentAlreadyExists]: {
    title: 'Duplicate Commitment Detected',
    message: 'A secure escrow commitment for this payment ID has already been registered.',
    recoveryGuidance: 'Please generate a new payment link with a new transaction ID.',
    actionLabel: 'Go Back',
    actionType: 'go_back',
  },
  [QuickexErrorCode.AlreadySpent]: {
    title: 'Funds Already Claimed',
    message: 'This escrow payment has already been spent or claimed by the recipient.',
    recoveryGuidance: 'Check your transaction history or contact the recipient to confirm receipt.',
    actionLabel: 'Refresh History',
    actionType: 'refresh_balance',
  },
  [QuickexErrorCode.InvalidCommitment]: {
    title: 'Invalid Escrow Commitment',
    message: 'The secure commitment verification failed on-chain.',
    recoveryGuidance: 'Regenerate the link and try the payment again.',
    actionLabel: 'Go Back',
    actionType: 'go_back',
  },
  [QuickexErrorCode.CommitmentMismatch]: {
    title: 'Commitment Verification Failed',
    message: 'The commitment parameters do not match the on-chain recorded details.',
    recoveryGuidance: 'This may happen if the payment parameters were edited manually.',
    actionLabel: 'Go Back',
    actionType: 'go_back',
  },
  [QuickexErrorCode.EscrowExpired]: {
    title: 'Escrow Lockup Expired',
    message: 'This secure payment lockup has expired. The funds can no longer be processed.',
    recoveryGuidance: 'Please ask the sender to create a new payment link.',
    actionLabel: 'Go Back',
    actionType: 'go_back',
  },
  [QuickexErrorCode.EscrowNotExpired]: {
    title: 'Refund Locked',
    message: 'You cannot claim a refund yet because the lockup expiration time has not been reached.',
    recoveryGuidance: 'Wait for the lockup period to expire before requesting a refund.',
    actionLabel: 'Try Again Later',
    actionType: 'retry',
  },
  [QuickexErrorCode.InvalidOwner]: {
    title: 'Unauthorized Owner',
    message: 'Only the original sender of this payment has the authority to claim a refund.',
    recoveryGuidance: 'Please connect the Stellar wallet address that originally paid this link.',
    actionLabel: 'Switch Wallet',
    actionType: 'dismiss',
  },
  [QuickexErrorCode.NoArbiter]: {
    title: 'No Arbiter Configured',
    message: 'This escrow transaction does not have an assigned arbiter, so a dispute cannot be raised.',
    recoveryGuidance: 'Please complete the transaction directly or contact support.',
    actionLabel: 'Contact Support',
    actionType: 'contact_support',
  },
  [QuickexErrorCode.InvalidDisputeState]: {
    title: 'Invalid Dispute State',
    message: 'The transaction is not in a status that allows dispute operations.',
    recoveryGuidance: 'Make sure the transaction has not already been completed or expired.',
    actionLabel: 'Dismiss',
    actionType: 'dismiss',
  },
  [QuickexErrorCode.NotArbiter]: {
    title: 'Unauthorized Arbiter',
    message: 'You are not designated as the arbiter for this escrow transaction.',
    recoveryGuidance: 'Verify you are logged in with the arbiter wallet address.',
    actionLabel: 'Switch Wallet',
    actionType: 'dismiss',
  },
  [QuickexErrorCode.OperationPaused]: {
    title: 'Action Temporarily Disabled',
    message: 'This specific contract operation has been temporarily paused by administrators.',
    recoveryGuidance: 'Please wait a short while and try the action again.',
    actionLabel: 'Retry Operation',
    actionType: 'retry',
  },
  [QuickexErrorCode.InvalidContractVersion]: {
    title: 'Version Mismatch',
    message: 'The smart contract version is incompatible with this mobile application version.',
    recoveryGuidance: 'Check the App Store or Google Play Store to update your QuickEx mobile app.',
    actionLabel: 'Update App',
    actionType: 'contact_support',
  },
  [QuickexErrorCode.Overpayment]: {
    title: 'Payment Exceeds Limit',
    message: 'The sent amount is higher than the remaining balance due on this link.',
    recoveryGuidance: 'Reduce your payment amount to match the exact remaining balance.',
    actionLabel: 'Adjust Amount',
    actionType: 'dismiss',
  },
  [QuickexErrorCode.ReentrancyDetected]: {
    title: 'Security Intervention',
    message: 'A nested or reentrant smart contract call was blocked to prevent potential exploit.',
    recoveryGuidance: 'Please close other pending wallet actions and try again.',
    actionLabel: 'Retry Payment',
    actionType: 'retry',
  },
  [QuickexErrorCode.HookAlreadyRegistered]: {
    title: 'Integration Hook Exists',
    message: 'The custom notification hook for this payment registry has already been configured.',
    recoveryGuidance: 'No action is needed as the configuration is already present.',
    actionLabel: 'Dismiss',
    actionType: 'dismiss',
  },
  [QuickexErrorCode.HookNotRegistered]: {
    title: 'Integration Hook Missing',
    message: 'The custom notification hook has not been registered.',
    recoveryGuidance: 'Please register the hook or contact support.',
    actionLabel: 'Contact Support',
    actionType: 'contact_support',
  },
  [QuickexErrorCode.NotAnArbiter]: {
    title: 'Unauthorized Arbiter',
    message: 'The wallet connected is not part of the assigned dispute arbiters group.',
    recoveryGuidance: 'Please connect one of the designated arbiter wallets.',
    actionLabel: 'Switch Wallet',
    actionType: 'dismiss',
  },
  [QuickexErrorCode.ArbiterAlreadyVoted]: {
    title: 'Vote Already Recorded',
    message: 'You have already submitted your arbiter vote for this dispute resolution.',
    recoveryGuidance: 'Multiple votes from the same arbiter account are not allowed.',
    actionLabel: 'Dismiss',
    actionType: 'dismiss',
  },
  [QuickexErrorCode.InsufficientVotes]: {
    title: 'Resolution Pending',
    message: 'There are not enough arbiter approvals to finalize this dispute decision.',
    recoveryGuidance: 'Wait for other designated arbiters to record their votes.',
    actionLabel: 'Refresh Status',
    actionType: 'refresh_balance',
  },
  [QuickexErrorCode.StealthAddressMismatch]: {
    title: 'Address Verification Failed',
    message: 'The generated stealth receiver address does not match the provided public key.',
    recoveryGuidance: 'This transaction cannot be completed securely. Please request a new payment link.',
    actionLabel: 'Go Back',
    actionType: 'go_back',
  },
  [QuickexErrorCode.StealthAddressAlreadyUsed]: {
    title: 'Stealth Key Reuse Blocked',
    message: 'This derived stealth address has already been used for an active escrow.',
    recoveryGuidance: 'For privacy, please generate a new stealth key and try again.',
    actionLabel: 'Regenerate Link',
    actionType: 'go_back',
  },
  [QuickexErrorCode.StealthEscrowNotFound]: {
    title: 'Stealth Escrow Not Found',
    message: 'No active stealth escrow transaction was found for the given stealth key.',
    recoveryGuidance: 'Verify the key details or wait for the on-chain registry to sync.',
    actionLabel: 'Refresh',
    actionType: 'refresh_balance',
  },
  [QuickexErrorCode.NonceAlreadyUsed]: {
    title: 'Transaction Signature Reused',
    message: 'This transaction replay defense was triggered because the signature nonce has already been consumed.',
    recoveryGuidance: 'Disconnect your wallet, wait 10 seconds, and authorize a new transaction request.',
    actionLabel: 'Refresh Connection',
    actionType: 'refresh_balance',
  },
  [QuickexErrorCode.SignatureExpired]: {
    title: 'Signature Timed Out',
    message: 'The signature authorization window expired before submission to the network.',
    recoveryGuidance: 'Please sign a new transaction request and submit it immediately.',
    actionLabel: 'Retry Transaction',
    actionType: 'retry',
  },
  [QuickexErrorCode.InternalError]: {
    title: 'On-chain Internal Error',
    message: 'The smart contract encountered an unhandled internal exception or execution bug.',
    recoveryGuidance: 'Please check your connection and network fees, or try again later.',
    actionLabel: 'Retry',
    actionType: 'retry',
  },
  [QuickexErrorCode.InvalidTimeout]: {
    title: 'Invalid Lockup Duration',
    message: 'The specified lockup expiration window is invalid or too short.',
    recoveryGuidance: 'Adjust the refund delay setting and try again.',
    actionLabel: 'Dismiss',
    actionType: 'dismiss',
  },
};

/**
 * Attempts to parse an error to extract a QuickexErrorCode.
 * It handles raw numbers, strings, and standard error objects.
 */
export function extractContractErrorCode(error: any): number | string | null {
  if (error === null || error === undefined) {
    return null;
  }

  // Case 1: error is a number (direct error code)
  if (typeof error === 'number') {
    return error;
  }

  // Case 2: error is a string
  if (typeof error === 'string') {
    // Look for exact code matching
    const codeMatch = error.match(/\b(10[0-2]|20[0-2]|30[0-9]|31[0-9]|32[0-1]|40[0-2]|50[0-1]|90[0-1])\b/);
    if (codeMatch) {
      return parseInt(codeMatch[0], 10);
    }

    // Check for enum name matches (case insensitive)
    const upperError = error.toUpperCase();
    for (const key of Object.keys(QuickexErrorCode)) {
      if (isNaN(Number(key))) { // filter out reverse mapping entries
        if (upperError.includes(key.toUpperCase())) {
          return QuickexErrorCode[key as keyof typeof QuickexErrorCode];
        }
      }
    }
    return error; // return string directly if no number/enum name matches
  }

  // Case 3: error is an object
  if (typeof error === 'object') {
    // Check known properties recursively
    const fields = ['code', 'status', 'errorCode', 'error', 'message'];
    for (const field of fields) {
      if (field in error && error[field] !== undefined) {
        const val = extractContractErrorCode(error[field]);
        if (val !== null) {
          return val;
        }
      }
    }
  }

  return null;
}

/**
 * Maps any raw contract error (number, string, object) to a user-friendly MappedContractError object.
 */
export function mapContractError(error: any): MappedContractError {
  const code = extractContractErrorCode(error);

  if (code !== null && typeof code === 'number' && ERROR_MAPPINGS[code]) {
    return {
      code,
      ...ERROR_MAPPINGS[code],
    };
  }

  // Fallback for custom string-only contract errors or other types
  const stringCode = code !== null ? String(code) : 'Unknown';
  return {
    code: stringCode,
    title: 'Contract Execution Failed',
    message: typeof error === 'string' 
      ? error 
      : error?.message || 'The secure smart contract operation could not be completed.',
    recoveryGuidance: 'Check the connection in your Stellar wallet, ensure you have enough network fees (XLM), and try again.',
    actionLabel: 'Try Again',
    actionType: 'retry',
  };
}
