@Injectable()
export class TemplateService {
  render(template: string, data: Record<string, any>) {
    return template.replace(/\{\{(\w+)\}\}/g, (_, key) => {
      return data[key] ?? "";
    });
  }

  getTemplate(event: NotificationEventType) {
    const templates = {
      EscrowDeposited: {
        title: "Escrow Deposit",
        body: "You deposited {{amountStroops}} into escrow.",
      },
      "payment.received": {
        title: "Payment Received",
        body: "You received {{amountStroops}} from {{sender}}.",
      },
    };

    return templates[event] || null;
  }
}