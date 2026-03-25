import { Controller, Get, Query } from "@nestjs/common";
import { ApiTags, ApiOperation, ApiResponse } from "@nestjs/swagger";

import { HorizonService } from "../transactions/horizon.service";

type RecentPaymentsQuery = {
  address: string;
  since?: string; // ISO timestamp or epoch ms
  limit?: number;
};

@ApiTags("payments")
@Controller("payments")
export class PaymentsController {
  constructor(private readonly horizonService: HorizonService) {}

  @Get("recent")
  @ApiOperation({
    summary: "Fetch recent payments for an address (since timestamp)",
  })
  @ApiResponse({ status: 200, description: "List of recent payments" })
  async recent(@Query() query: RecentPaymentsQuery) {
    const { address, since, limit = 20 } = query;

    if (!address) {
      return { items: [] };
    }

    // HorizonService.getPayments returns items sorted desc by created_at
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
