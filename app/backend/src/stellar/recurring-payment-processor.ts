import { Injectable, Logger } from '@nestjs/common';
import { Keypair, TransactionBuilder, Networks, Asset, Memo, Horizon, Operation } from '@stellar/stellar-sdk';
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
  private readonly server: Horizon.Server;

  constructor(private readonly config: ConfigService) {
    const network = this.config.get<string>('stellar.network') || 'testnet';
    
    if (network === 'mainnet') {
      this.horizonUrl = 'https://horizon.stellar.org';
      this.networkPassphrase = Networks.PUBLIC;
    } else {
      this.horizonUrl = 'https://horizon-testnet.stellar.org';
      this.networkPassphrase = Networks.TESTNET;
    }

    this.server = new Horizon.Server(this.horizonUrl);
    
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
      referenceId,
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
      transaction.sign(sourceKeypair);

      // Submit to Stellar
      const response = await this.server.submitTransaction(transaction);

      this.logger.log(`Payment submitted successfully: ${response.hash}`);

      return response.hash;
    } catch (error: any) {
      this.logger.error(`Failed to submit payment: ${error.message}`, error.stack);
      
      if (error.response?.data?.extras?.result_codes) {
        this.logger.error(`Stellar error codes: ${JSON.stringify(error.response.data.extras.result_codes)}`);
      }
      
      throw new Error(`Payment submission failed: ${error.message}`);
    }
  }

  /**
   * Verify if a payment was claimed (for claimable balances)
   */
  async verifyPaymentCompletion(transactionHash: string): Promise<boolean> {
    try {
      const tx = await this.server.transactions().transaction(transactionHash).call();
      return tx.successful;
    } catch (error: any) {
      this.logger.error(`Failed to verify payment: ${error.message}`);
      return false;
    }
  }

  // ---------------------------------------------------------------------------
  // Private Helper Methods
  // ---------------------------------------------------------------------------

  private getSourceKeypair(): Keypair {
    const secretKey = this.config.get<string>('STELLAR_SECRET_KEY');
    
    if (!secretKey) {
      throw new Error('STELLAR_SECRET_KEY environment variable is not set');
    }

    return Keypair.fromSecret(secretKey);
  }

  private async buildPaymentTransaction(params: {
    sourceAccount: Horizon.AccountResponse;
    recipientAddress: string;
    amount: string | number;
    assetCode: string;
    assetIssuer?: string;
    memo?: string;
    memoType?: string;
  }): Promise<any> {
    const {
      sourceAccount,
      recipientAddress,
      amount,
      assetCode,
      assetIssuer,
      memo,
      memoType,
    } = params;

    // Determine asset type
    const asset = this.createAsset(assetCode, assetIssuer);

    // Build base transaction
    let transactionBuilder = new TransactionBuilder(sourceAccount, {
      fee: (await this.server.fetchBaseFee()).toString(),
      networkPassphrase: this.networkPassphrase,
    });

    // Add payment operation
    const paymentOperation = this.createPaymentOperation({
      recipientAddress,
      amount,
      asset,
    });

    transactionBuilder = transactionBuilder.addOperation(paymentOperation);

    // Add memo if provided
    if (memo) {
      const memoObj = this.createMemo(memo, memoType);
      transactionBuilder = transactionBuilder.addMemo(memoObj);
    }

    // Set timeout
    transactionBuilder = transactionBuilder.setTimeout(180); // 3 minutes

    return transactionBuilder.build();
  }

  private createAsset(assetCode: string, assetIssuer?: string): Asset {
    if (assetCode === 'XLM' || !assetIssuer) {
      return Asset.native();
    }

    return new Asset(assetCode, assetIssuer);
  }

  private createPaymentOperation(params: {
    recipientAddress: string;
    amount: string | number;
    asset: Asset;
  }): any {
    const { recipientAddress, amount, asset } = params;

    const amountStr = typeof amount === 'number' ? amount.toFixed(7) : amount;

    return Operation.payment({
      destination: recipientAddress,
      asset: asset,
      amount: amountStr,
    });
  }

  private createMemo(memo: string, memoType?: string): Memo {
    const type = memoType || 'text';

    switch (type) {
      case 'id':
        return Memo.id(memo);
      case 'hash':
        return Memo.hash(memo);
      case 'return':
        return Memo.return(memo);
      case 'text':
      default:
        return Memo.text(memo);
    }
  }
}
