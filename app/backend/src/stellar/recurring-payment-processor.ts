import { Injectable, Logger } from '@nestjs/common';
import * as StellarSdk from '@stellar/stellar-sdk';
import { ConfigService } from '@nestjs/config';

export interface RecurringPaymentParams {
  recipientAddress: string;
  amount: number;
  assetCode: string;
  assetIssuer?: string;
  memo?: string;
  memoType?: string;
  referenceId?: string;
}

/**
 * Handles Stellar transaction processing for recurring payments
 */
@Injectable()
export class RecurringPaymentProcessor {
  private readonly logger = new Logger(RecurringPaymentProcessor.name);
  private readonly horizonUrl: string;
  private readonly networkPassphrase: string;
  private readonly server: StellarSdk.Horizon.Server;

  constructor(private readonly config: ConfigService) {
    const network = this.config.get<string>('stellar.network') || 'testnet';
    
    if (network === 'mainnet') {
      this.horizonUrl = 'https://horizon.stellar.org';
      this.networkPassphrase = StellarSdk.Networks.PUBLIC;
    } else {
      this.horizonUrl = 'https://horizon-testnet.stellar.org';
      this.networkPassphrase = StellarSdk.Networks.TESTNET;
    }

    this.server = new StellarSdk.Horizon.Server(this.horizonUrl);
    
    this.logger.log(`Recurring payment processor initialized (${network} → ${this.horizonUrl})`);
  }

  /**
   * Submit a recurring payment transaction to Stellar
   */
  async submitRecurringPayment(params: RecurringPaymentParams): Promise<string> {
    const {
      recipientAddress,
      amount,
      assetCode,
      assetIssuer,
      memo,
      memoType,
    } = params;

    try {
      this.logger.log(`Submitting recurring payment: ${amount} ${assetCode} to ${recipientAddress}`);

      // Get source account (platform account that will fund the payments)
      const sourceKeypair = this.getSourceKeypair();
      const sourceAccount = await this.server.loadAccount(sourceKeypair.publicKey());

      // Build transaction
      const transaction = await this.buildPaymentTransaction({
        sourceAccount,
        recipientAddress,
        amount,
        assetCode,
        assetIssuer,
        memo,
        memoType,
      });

      // Sign transaction
      const builtTransaction = transaction.build();
      builtTransaction.sign(sourceKeypair);

      // Submit to Stellar
      const response = await this.server.submitTransaction(builtTransaction);

      this.logger.log(`Payment submitted successfully: ${response.hash}`);

      return response.hash;
    } catch (error: unknown) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      this.logger.error(`Failed to submit payment: ${errorMessage}`, error instanceof Error ? error.stack : undefined);
      
      if ((error as { response?: { data?: { extras?: { result_codes?: unknown } } } }).response?.data?.extras?.result_codes) {
        const errorData = error as { response: { data: { extras: { result_codes: unknown } } } };
        this.logger.error(`Stellar error codes: ${JSON.stringify(errorData.response.data.extras.result_codes)}`);
      }
      
      throw new Error(`Payment submission failed: ${errorMessage}`);
    }
  }

  /**
   * Verify if a payment was claimed (for claimable balances)
   */
  async verifyPaymentCompletion(transactionHash: string): Promise<boolean> {
    try {
      const tx = await this.server.transactions().transaction(transactionHash).call();
      return tx.successful;
    } catch (error: unknown) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      this.logger.error(`Failed to verify payment: ${errorMessage}`);
      return false;
    }
  }

  // ---------------------------------------------------------------------------
  // Private Helper Methods
  // ---------------------------------------------------------------------------

  private getSourceKeypair(): StellarSdk.Keypair {
    const secretKey = this.config.get<string>('STELLAR_SECRET_KEY');
    
    if (!secretKey) {
      throw new Error('STELLAR_SECRET_KEY environment variable is not set');
    }

    return StellarSdk.Keypair.fromSecret(secretKey);
  }

  private async buildPaymentTransaction(params: {
    sourceAccount: StellarSdk.Horizon.AccountResponse;
    recipientAddress: string;
    amount: string | number;
    assetCode: string;
    assetIssuer?: string;
    memo?: string;
    memoType?: string;
  }): Promise<StellarSdk.TransactionBuilder> {
    const { sourceAccount, recipientAddress, amount, assetCode, assetIssuer, memo, memoType } = params;

    // Create asset
    const asset = this.createAsset(assetCode, assetIssuer);

    // Create payment operation
    const paymentOperation = this.createPaymentOperation({
      recipientAddress,
      amount,
      asset,
    });

    // Create memo if provided
    const memoObj = memo ? this.createMemo(memo, memoType) : undefined;

    // Build transaction
    const transactionBuilder = new StellarSdk.TransactionBuilder(sourceAccount, {
      fee: '100',
      networkPassphrase: this.networkPassphrase,
    });

    transactionBuilder.addOperation(paymentOperation);

    if (memoObj) {
      transactionBuilder.addMemo(memoObj);
    }

    transactionBuilder.setTimeout(300);

    return transactionBuilder;
  }

  private createAsset(assetCode: string, assetIssuer?: string): StellarSdk.Asset {
    if (assetCode === 'XLM' || !assetIssuer) {
      return StellarSdk.Asset.native();
    }

    return new StellarSdk.Asset(assetCode, assetIssuer);
  }

  private createPaymentOperation(params: {
    recipientAddress: string;
    amount: string | number;
    asset: StellarSdk.Asset;
  }): ReturnType<typeof StellarSdk.Operation.payment> {
    const { recipientAddress, amount, asset } = params;

    const amountStr = typeof amount === 'number' ? amount.toFixed(7) : amount;

    return StellarSdk.Operation.payment({
      destination: recipientAddress,
      asset: asset,
      amount: amountStr,
    });
  }

  private createMemo(memo: string, memoType?: string): StellarSdk.Memo<StellarSdk.MemoType> {
    const type = memoType || 'text';

    switch (type) {
      case 'id':
        return StellarSdk.Memo.id(memo);
      case 'hash':
        return StellarSdk.Memo.hash(memo);
      case 'return':
        return StellarSdk.Memo.return(memo);
      case 'text':
      default:
        return StellarSdk.Memo.text(memo);
    }
  }
}
