import { Injectable, Logger } from "@nestjs/common";

import { HorizonService } from "../transactions/horizon.service";

export type RecentPaymentsOptions = {
  address: string;
  since?: string;
  limit?: number;
};

@Injectable()
export class PaymentsService {
  private readonly logger = new Logger(PaymentsService.name);

  constructor(private readonly horizonService: HorizonService) {}

  async getRecentPayments(options: RecentPaymentsOptions) {
    const { address, since, limit = 20 } = options;

    if (!address) {
      return { items: [] };
    }

    const resp = await this.horizonService.getPayments(
      address,
      undefined,
      Number(limit),
    );

    const sinceTs = since ? parseSince(since) : undefined;

    const filtered = sinceTs
      ? resp.items.filter((it) => new Date(it.timestamp).getTime() > sinceTs)
      : resp.items;

    return { items: filtered };
  }
}

function parseSince(raw?: string): number | undefined {
  if (!raw) return undefined;
  // accept epoch ms or ISO
  const n = Number(raw);
  if (!Number.isNaN(n) && n > 0) return n;
  const d = Date.parse(raw);
  return Number.isNaN(d) ? undefined : d;
}
