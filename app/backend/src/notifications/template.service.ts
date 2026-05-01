import { Injectable } from '@nestjs/common';

@Injectable()
export class TemplateService {
  render(template: string, data: Record<string, unknown>): string {
    return template.replace(/\{\{(\w+)\}\}/g, (_, key: string): string => {
      const value = data[key];
      return typeof value === 'string' ? value : ``;
    });
  }

  getTemplate(eventType: string): { title: string; body: string } | undefined {
    const templates: Record<string, { title: string; body: string }> = {
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