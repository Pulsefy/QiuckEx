import { ScamAlertType, ScamSeverity } from "../constants/scam-rules.constants";

/**
 * Individual scam alert flag
 */
export interface ScamAlert {
	/** Type of scam detected */
	type: ScamAlertType;
	/** Severity level of the alert */
	severity: ScamSeverity;
	/** Human-readable message explaining the issue */
	message: string;
	/** Recommended action for the user */
	recommendation: string;
}

/**
 * Payment link data to be scanned
 */
export interface PaymentLinkData {
	/** Asset code (e.g., XLM, USDC) */
	assetCode: string;
	/** Payment amount */
	amount: number;
	/** Optional memo/reference */
	memo?: string;
	/** Recipient address (for additional checks) */
	recipientAddress?: string;
}

/**
 * Scan result with all detected alerts
 */
export interface ScanResult {
	/** Whether the link appears safe */
	isSafe: boolean;
	/** Overall risk score (0-100) */
	riskScore: number;
	/** List of detected alerts */
	alerts: ScamAlert[];
	/** Number of critical alerts */
	criticalCount: number;
	/** Number of high severity alerts */
	highCount: number;
	/** Number of medium severity alerts */
	mediumCount: number;
	/** Number of low severity alerts */
	lowCount: number;
}
