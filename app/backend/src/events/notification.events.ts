export enum NotificationEvent {
  PaymentReceived = 'payment.received',
  UsernameClaimed = 'username.claimed',
}

export class PaymentReceivedEvent {
  constructor(
    public readonly txHash: string,
    public readonly amount: string,
    public readonly sender: string,
  ) {}
}

export class UsernameClaimedEvent {
  constructor(
    public readonly username: string,
    public readonly publicKey: string,
  ) {}
}