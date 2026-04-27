import { ApiProperty, ApiPropertyOptional } from "@nestjs/swagger";
import { LinkState } from "../../links/link-state-machine";

export class PaymentLinkStatusDto {
  @ApiProperty({
    description: "Current state of the payment link",
    enum: ["DRAFT", "ACTIVE", "EXPIRED", "PAID", "REFUNDED"],
    example: "ACTIVE",
  })
  state!: LinkState;

  @ApiProperty({
    description: "Username associated with the payment link",
    example: "john_doe",
  })
  username!: string;

  @ApiProperty({
    description: "Payment amount",
    example: "100.0000000",
  })
  amount!: string;

  @ApiProperty({
    description: "Asset code",
    example: "XLM",
  })
  asset!: string;

  @ApiProperty({
    description: "Optional memo text",
    example: "Payment for services",
    nullable: true,
  })
  memo!: string | null;

  @ApiProperty({
    description: "Destination Stellar public key",
    example: "GABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890",
  })
  destinationPublicKey!: string;

  @ApiProperty({
    description: "Payment link expiration date",
    example: "2026-05-27T12:00:00.000Z",
    nullable: true,
  })
  expiresAt!: Date | null;

  @ApiProperty({
    description: "Transaction hash if payment is complete",
    example: "abc123...",
    nullable: true,
  })
  transactionHash!: string | null;

  @ApiProperty({
    description: "Date when payment was completed",
    example: "2026-04-27T10:30:00.000Z",
    nullable: true,
  })
  paidAt!: Date | null;

  @ApiProperty({
    description: "Swap options available for this payment link",
    type: "array",
    nullable: true,
  })
  swapOptions?: Array<{
    sourceAmount: string;
    sourceAsset: string;
    destinationAmount: string;
    destinationAsset: string;
    hopCount: number;
    pathHops: string[];
    rateDescription: string;
  }> | null;

  @ApiProperty({
    description: "Whether the link can accept multiple assets",
    example: false,
  })
  acceptsMultipleAssets!: boolean;

  @ApiProperty({
    description: "List of accepted asset codes",
    type: [String],
    nullable: true,
  })
  acceptedAssets!: string[] | null;

  @ApiPropertyOptional({
    description: "User-friendly message explaining the current state",
    example: "This payment link is active and ready to receive payment",
  })
  userMessage?: string;

  @ApiPropertyOptional({
    description: "Actions available to the user in the current state",
    example: ["pay", "share"],
  })
  availableActions?: string[];
}
