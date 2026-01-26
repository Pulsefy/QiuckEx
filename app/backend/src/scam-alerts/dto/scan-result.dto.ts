import { ApiProperty } from "@nestjs/swagger";
import { ScamAlertType, ScamSeverity } from "../constants/scam-rules.constants";

/**
 * Individual alert in the scan result
 */
export class ScamAlertDto {
	@ApiProperty({
		description: "Type of scam alert detected",
		enum: ScamAlertType,
		example: ScamAlertType.MISSING_MEMO,
	})
	type: ScamAlertType;

	@ApiProperty({
		description: "Severity level of the alert",
		enum: ScamSeverity,
		example: ScamSeverity.MEDIUM,
	})
	severity: ScamSeverity;

	@ApiProperty({
		description: "Human-readable message",
		example: "Payment link requires a memo but none is provided",
	})
	message: string;

	@ApiProperty({
		description: "Recommended action",
		example: "Add a unique memo to identify your payment",
	})
	recommendation: string;
}

/**
 * Complete scan result response
 */
export class ScanResultDto {
	@ApiProperty({
		description: "Whether the payment link appears safe",
		example: false,
	})
	isSafe: boolean;

	@ApiProperty({
		description: "Overall risk score (0-100, higher is riskier)",
		example: 65,
	})
	riskScore: number;

	@ApiProperty({
		description: "List of detected scam alerts",
		type: [ScamAlertDto],
	})
	alerts: ScamAlertDto[];

	@ApiProperty({
		description: "Number of critical severity alerts",
		example: 1,
	})
	criticalCount: number;

	@ApiProperty({
		description: "Number of high severity alerts",
		example: 0,
	})
	highCount: number;

	@ApiProperty({
		description: "Number of medium severity alerts",
		example: 1,
	})
	mediumCount: number;

	@ApiProperty({
		description: "Number of low severity alerts",
		example: 0,
	})
	lowCount: number;
}
