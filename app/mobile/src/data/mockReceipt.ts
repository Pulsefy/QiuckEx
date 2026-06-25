import type { ReceiptData } from '../types/receipt';

export const mockReceiptPending: ReceiptData = {
  id: 'rec_test_001',
  amount: '50.00',
  asset: 'USDC',
  sender: 'GABCDEF1234567890ABCDEF1234567890ABCDEF1234567890AB',
  recipient: 'G1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF12',
  memo: 'Invoice #1234',
  status: 'pending',
  metadata: {
    receiptHash: '0xabc123def4567890123456789012345678901234abcdef5678901234567890ab',
    createdAt: '2026-06-25 14:30:00 UTC',
    expiresAt: '2026-06-25 15:30:00 UTC',
  },
  contract: {
    contractId: 'C1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab',
    wasmHash: '0xwasm7890123456789012345678901234567890123456789012345678901234',
    deployedAt: '2026-01-15 10:00:00 UTC',
    networkPassphrase: 'Test SDF Network ; September 2015',
  },
  network: {
    network: 'testnet',
    horizonUrl: 'https://horizon-testnet.stellar.org',
    ledger: 1234567,
    ledgerCloseTime: '2026-06-25 14:30:15 UTC',
  },
  timeline: [
    {
      id: '1',
      step: 'created',
      title: 'Payment Created',
      description: 'Payment link generated and shared with recipient.',
      timestamp: '14:30:00',
      status: 'completed',
    },
    {
      id: '2',
      step: 'submitted',
      title: 'Transaction Submitted',
      description: 'Transaction submitted to the Stellar network.',
      timestamp: '14:30:05',
      status: 'completed',
      txHash: '0xtx1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab',
    },
    {
      id: '3',
      step: 'validated',
      title: 'Awaiting Validation',
      description: 'Waiting for network consensus and ledger confirmation.',
      timestamp: '14:30:10',
      status: 'current',
    },
    {
      id: '4',
      step: 'executed',
      title: 'Contract Execution',
      description: 'Smart contract will execute upon validation.',
      timestamp: '',
      status: 'upcoming',
    },
    {
      id: '5',
      step: 'settled',
      title: 'Funds Settled',
      description: 'Funds transferred to recipient wallet.',
      timestamp: '',
      status: 'upcoming',
    },
  ],
};

export const mockReceiptSuccess: ReceiptData = {
  ...mockReceiptPending,
  id: 'rec_test_002',
  status: 'success',
  timeline: [
    { ...mockReceiptPending.timeline[0], status: 'completed' },
    { ...mockReceiptPending.timeline[1], status: 'completed' },
    {
      id: '3',
      step: 'validated',
      title: 'Validated',
      description: 'Transaction confirmed in ledger 1234567.',
      timestamp: '14:30:12',
      status: 'completed',
      txHash: '0xtx1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab',
    },
    {
      id: '4',
      step: 'executed',
      title: 'Contract Executed',
      description: 'Smart contract executed successfully.',
      timestamp: '14:30:15',
      status: 'completed',
    },
    {
      id: '5',
      step: 'settled',
      title: 'Funds Settled',
      description: '50.00 USDC transferred to recipient.',
      timestamp: '14:30:18',
      status: 'completed',
    },
  ],
};

export const mockReceiptFailed: ReceiptData = {
  ...mockReceiptPending,
  id: 'rec_test_003',
  status: 'failed',
  timeline: [
    { ...mockReceiptPending.timeline[0], status: 'completed' },
    { ...mockReceiptPending.timeline[1], status: 'completed' },
    {
      id: '3',
      step: 'validated',
      title: 'Validation Failed',
      description: 'Insufficient balance for transaction.',
      timestamp: '14:30:12',
      status: 'failed',
      txHash: '0xtxfail1234567890abcdef1234567890abcdef1234567890abcdef1234567890',
    },
    {
      id: '4',
      step: 'refunded',
      title: 'Auto-Refund Initiated',
      description: 'No funds were deducted. Transaction cancelled.',
      timestamp: '14:30:13',
      status: 'completed',
    },
  ],
};

export const mockReceiptRefund: ReceiptData = {
  ...mockReceiptPending,
  id: 'rec_test_004',
  status: 'refund',
  amount: '50.00',
  timeline: [
    { ...mockReceiptPending.timeline[0], status: 'completed' },
    { ...mockReceiptPending.timeline[1], status: 'completed' },
    {
      id: '3',
      step: 'validated',
      title: 'Validated',
      description: 'Transaction confirmed in ledger.',
      timestamp: '14:30:12',
      status: 'completed',
    },
    {
      id: '4',
      step: 'executed',
      title: 'Contract Executed',
      description: 'Payment conditions were not met.',
      timestamp: '14:30:15',
      status: 'completed',
    },
    {
      id: '5',
      step: 'refunded',
      title: 'Refunded',
      description: '50.00 USDC returned to sender.',
      timestamp: '14:35:22',
      status: 'completed',
      txHash: '0xtxrefund1234567890abcdef1234567890abcdef1234567890abcdef1234567890',
    },
  ],
};