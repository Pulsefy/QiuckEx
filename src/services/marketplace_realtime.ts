/**
 * Recurring payment link builder and real-time marketplace update client for QiuckEx.
 */

export interface RecurringPaymentLink {
  linkId: string;
  creatorAddress: string;
  amount: number;
  asset: string;
  interval: 'daily' | 'weekly' | 'monthly';
  active: boolean;
}

export class RecurringPaymentService {
  private links = new Map<string, RecurringPaymentLink>();

  public createRecurringLink(
    creatorAddress: string,
    amount: number,
    asset: string = 'XLM',
    interval: 'daily' | 'weekly' | 'monthly' = 'monthly'
  ): RecurringPaymentLink {
    const linkId = `rpay_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`;
    const link: RecurringPaymentLink = {
      linkId,
      creatorAddress,
      amount,
      asset,
      interval,
      active: true,
    };
    this.links.set(linkId, link);
    return link;
  }

  public getLink(linkId: string): RecurringPaymentLink | undefined {
    return this.links.get(linkId);
  }
}

export interface MarketplaceUpdate {
  listingId: string;
  price: number;
  buyerAddress?: string;
  timestamp: number;
}

export class RealtimeMarketplaceClient {
  private listeners: Array<(update: MarketplaceUpdate) => void> = [];
  private isConnected: boolean = false;

  public connect(wsEndpoint: string): void {
    this.isConnected = true;
    console.log(`Connected to real-time marketplace at ${wsEndpoint}`);
  }

  public subscribe(callback: (update: MarketplaceUpdate) => void): () => void {
    this.listeners.push(callback);
    return () => {
      this.listeners = this.listeners.filter(cb => cb !== callback);
    };
  }

  public broadcastUpdate(update: MarketplaceUpdate): void {
    if (!this.isConnected) return;
    for (const listener of this.listeners) {
      listener(update);
    }
  }

  public disconnect(): void {
    this.isConnected = false;
    this.listeners = [];
  }
}
