import { useCallback } from 'react';
import { Share, Platform } from 'react-native';
import type { ReceiptData, ShareableReceipt } from '../types/receipt';

interface UseShareReceiptReturn {
  share: (receipt: ReceiptData) => Promise<void>;
  generateSupportText: (receipt: ReceiptData) => string;
}

/**
 * Generate formatted receipt text for support workflows
 */
function generateSupportText(receipt: ReceiptData): string {
  const lines = [
    '=== QuickEx Payment Receipt ===',
    '',
    `Amount: ${receipt.amount} ${receipt.asset}`,
    `Status: ${receipt.status.toUpperCase()}`,
    `From: ${receipt.sender}`,
    `To: ${receipt.recipient}`,
    '',
    '--- Metadata ---',
    `Receipt Hash: ${receipt.metadata.receiptHash}`,
    `Contract ID: ${receipt.contract.contractId}`,
    `Network: ${receipt.network.network.toUpperCase()}`,
    `Ledger: ${receipt.network.ledger}`,
    `Timestamp: ${receipt.network.ledgerCloseTime}`,
    '',
    '--- Timeline ---',
    ...receipt.timeline.map((event) => 
      `[${event.status.toUpperCase()}] ${event.title} — ${event.timestamp}`
    ),
    '',
    `Explorer: ${getExplorerUrl(receipt)}`,
    '',
    'For support, include this entire message.',
    '===============================',
  ];

  return lines.join('\n');
}

function getExplorerUrl(receipt: ReceiptData): string {
  const baseUrl = receipt.network.network === 'mainnet'
    ? 'https://stellar.expert/explorer/public'
    : 'https://stellar.expert/explorer/testnet';
  
  return `${baseUrl}/tx/${receipt.metadata.receiptHash}`;
}

function generateShareableReceipt(receipt: ReceiptData): ShareableReceipt {
  return {
    title: `QuickEx Payment — ${receipt.amount} ${receipt.asset}`,
    amount: receipt.amount,
    asset: receipt.asset,
    status: receipt.status,
    receiptHash: receipt.metadata.receiptHash,
    contractId: receipt.contract.contractId,
    network: receipt.network.network,
    explorerUrl: getExplorerUrl(receipt),
    supportText: generateSupportText(receipt),
  };
}

/**
 * Share receipt via native share sheet
 */
export function useShareReceipt(): UseShareReceiptReturn {
  const share = useCallback(async (receipt: ReceiptData) => {
    const shareable = generateShareableReceipt(receipt);
    
    try {
      await Share.share({
        title: shareable.title,
        message: shareable.supportText,
        url: shareable.explorerUrl, // iOS only
      }, {
        dialogTitle: 'Share Receipt',
        subject: shareable.title, // Email subject
      });
    } catch (error) {
      // User cancelled — no action needed
      if ((error as Error).message?.includes('cancelled')) return;
      console.error('Share error:', error);
    }
  }, []);

  return {
    share,
    generateSupportText,
  };
}