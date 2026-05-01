import { Injectable } from '@nestjs/common';
import { NotificationEventType } from '../types/notification.types';

@Injectable()
export class TemplateService {
  render(template: string, data: Record<string, unknown>): string {
    return template.replace(/\{\{(\w+)\}\}/g, (_, key: string): string => {
      const value = data[key];
      return typeof value === 'string' ? value : ``;
    });
  }

  getTemplate(event: NotificationEventType): { title: string; body: string } | null {
    const templates: Partial<Record<NotificationEventType, { title: string; body: string }>> = {
      EscrowDeposited: {
        title: "Escrow Deposit",
        body: "You deposited {{amountStroops}} into escrow.",
      },
      "payment.received": {
        title: "Payment Received",
        body: "You received {{amountStroops}} from {{sender}}.",
      },
      EscrowWithdrawn: {
        title: "Escrow Withdrawn",
        body: "You withdrew {{amountStroops}} from escrow.",
      },
      EscrowRefunded: {
        title: "Escrow Refunded",
        body: "You received a refund of {{amountStroops}}.",
      },
      "username.claimed": {
        title: "Username Claimed",
        body: "Your username {{username}} is now active.",
      },
      "recurring.payment.due": {
        title: "Payment Due",
        body: "A recurring payment of {{amount}} {{asset}} is due.",
      },
      "recurring.payment.executed": {
        title: "Payment Executed",
        body: "Recurring payment of {{amount}} {{asset}} executed.",
      },
      "recurring.payment.failed": {
        title: "Payment Failed",
        body: "Recurring payment of {{amount}} {{asset}} failed.",
      },
      "recurring.payment.cancelled": {
        title: "Payment Cancelled",
        body: "Recurring payment cancelled.",
      },
      "recurring.link.created": {
        title: "Link Created",
        body: "New recurring link created.",
      },
      "recurring.link.updated": {
        title: "Link Updated",
        body: "Recurring link updated.",
      },
      "recurring.link.paused": {
        title: "Link Paused",
        body: "Recurring link paused.",
      },
      "recurring.link.resumed": {
        title: "Link Resumed",
        body: "Recurring link resumed.",
      },
      "recurring.link.completed": {
        title: "Link Completed",
        body: "Recurring link completed.",
      },
    };

    return templates[event] || null;
  }
}