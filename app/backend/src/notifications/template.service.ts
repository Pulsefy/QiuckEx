@Injectable()
export class TemplateService {
  render(template: string, data: Record<string, any>) {
    return template.replace(/\{\{(\w+)\}\}/g, (_, key) => {
      return data[key] ?? "";
    });
  }

  getTemplate(eventType: string) {
    const templates = {
      EscrowDeposited: {
        title: "Escrow Deposit Confirmed",
        body: "Your escrow of {{amount}} has been deposited.",
      },
      "payment.received": {
        title: "Payment Received",
        body: "You received {{amount}} from {{sender}}.",
      },
    };

    return templates[eventType];
  }
}