import { ApiProperty } from "@nestjs/swagger";
import { IsString, IsNumber, IsOptional, Min } from "class-validator";

/**
 * DTO for scanning a payment link
 */
export class ScanLinkDto {
	@ApiProperty({
		description: "Asset code to be transferred",
		example: "USDC",
	})
	@IsString()
	assetCode: string;

	@ApiProperty({
		description: "Amount to be transferred",
		example: 100.5,
	})
	@IsNumber()
	@Min(0)
	amount: number;

	@ApiProperty({
		description: "Optional memo/reference for the payment",
		example: "Invoice-12345",
		required: false,
	})
	@IsString()
	@IsOptional()
	memo?: string;

	@ApiProperty({
		description: "Optional recipient address for additional verification",
		example: "GABC123...",
		required: false,
	})
	@IsString()
	@IsOptional()
	recipientAddress?: string;
}
