import { Controller, Get, Query } from "@nestjs/common";
import { ApiTags, ApiOperation, ApiResponse } from "@nestjs/swagger";

import { PaymentsService } from "./payments.service";

type RecentPaymentsQuery = {
  address: string;
  since?: string; // ISO timestamp or epoch ms
  limit?: number;
};

@ApiTags("payments")
@Controller("payments")
export class PaymentsController {
  constructor(private readonly paymentsService: PaymentsService) {}

  @Get("recent")
  @ApiOperation({
    summary: "Fetch recent payments for an address (since timestamp)",
  })
  @ApiResponse({ status: 200, description: "List of recent payments" })
  async recent(@Query() query: RecentPaymentsQuery) {
    const { address, since, limit } = query;

    return this.paymentsService.getRecentPayments({
      address,
      since,
      limit: limit ? Number(limit) : undefined,
    });
  }
}
