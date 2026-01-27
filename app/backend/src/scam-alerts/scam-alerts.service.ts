import { Injectable, Logger } from "@nestjs/common";
import {
	ASSETS_REQUIRING_MEMO,
	WHITELISTED_ASSETS,
	MAX_REASONABLE_AMOUNTS,
	SUSPICIOUS_MEMO_PATTERNS,
	SCAM_RULES,
	ScamAlertType,
	ScamSeverity,
} from "./constants/scam-rules.constants";
import type {
	PaymentLinkData,
	ScanResult,
	ScamAlert,
} from "./types/scam-alert.types";

@Injectable()
export class ScamAlertsService {
	private readonly logger = new Logger(ScamAlertsService.name);

	/**
	 * Scan a payment link for scam indicators
	 */
	scanLink(linkData: PaymentLinkData): ScanResult {
		this.logger.log(`Scanning link: ${JSON.stringify(linkData)}`);

		const alerts: ScamAlert[] = [];

		// Run all heuristic checks
		this.checkMissingMemo(linkData, alerts);
		this.checkHighAmount(linkData, alerts);
		this.checkUnknownAsset(linkData, alerts);
		this.checkSuspiciousMemo(linkData, alerts);

		// Calculate severity counts
		const counts = this.calculateSeverityCounts(alerts);

		// Calculate risk score
		const riskScore = this.calculateRiskScore(counts);

		// Determine if safe
		const isSafe = counts.criticalCount === 0 && riskScore < 50;

		this.logger.log(
			`Scan complete. Risk score: ${riskScore}, Alerts: ${alerts.length}`,
		);

		return {
			isSafe,
			riskScore,
			alerts,
			...counts,
		};
	}

	/**
	 * Check if memo is missing when required
	 */
	private checkMissingMemo(
		linkData: PaymentLinkData,
		alerts: ScamAlert[],
	): void {
		if (
			ASSETS_REQUIRING_MEMO.includes(linkData.assetCode.toUpperCase()) &&
			!linkData.memo
		) {
			alerts.push({
				...SCAM_RULES[ScamAlertType.MISSING_MEMO],
				type: ScamAlertType.MISSING_MEMO,
			});
		}
	}

	/**
	 * Check if amount is suspiciously high
	 */
	private checkHighAmount(
		linkData: PaymentLinkData,
		alerts: ScamAlert[],
	): void {
		const maxAmount =
			MAX_REASONABLE_AMOUNTS[linkData.assetCode.toUpperCase()] ||
			MAX_REASONABLE_AMOUNTS.DEFAULT;

		if (linkData.amount > maxAmount) {
			alerts.push({
				...SCAM_RULES[ScamAlertType.HIGH_AMOUNT],
				type: ScamAlertType.HIGH_AMOUNT,
			});
		}
	}

	/**
	 * Check if asset is not whitelisted
	 */
	private checkUnknownAsset(
		linkData: PaymentLinkData,
		alerts: ScamAlert[],
	): void {
		if (!WHITELISTED_ASSETS.includes(linkData.assetCode.toUpperCase())) {
			alerts.push({
				...SCAM_RULES[ScamAlertType.UNKNOWN_ASSET],
				type: ScamAlertType.UNKNOWN_ASSET,
			});
		}
	}

	/**
	 * Check for suspicious patterns in memo
	 */
	private checkSuspiciousMemo(
		linkData: PaymentLinkData,
		alerts: ScamAlert[],
	): void {
		if (!linkData.memo) return;

		// Check for external addresses in memo
		if (/G[A-Z0-9]{55}|0x[a-fA-F0-9]{40}/.test(linkData.memo)) {
			alerts.push({
				...SCAM_RULES[ScamAlertType.EXTERNAL_ADDRESS_IN_MEMO],
				type: ScamAlertType.EXTERNAL_ADDRESS_IN_MEMO,
			});
			return; // Critical alert, don't check further
		}

		// Check for urgency patterns
		if (/urgent|asap|immediately|now|hurry/i.test(linkData.memo)) {
			alerts.push({
				...SCAM_RULES[ScamAlertType.URGENCY_PATTERN],
				type: ScamAlertType.URGENCY_PATTERN,
			});
		}

		// Check against suspicious patterns
		for (const pattern of SUSPICIOUS_MEMO_PATTERNS) {
			if (pattern.test(linkData.memo)) {
				alerts.push({
					...SCAM_RULES[ScamAlertType.SUSPICIOUS_MEMO],
					type: ScamAlertType.SUSPICIOUS_MEMO,
				});
				break; // Only add once
			}
		}
	}

	/**
	 * Calculate severity counts
	 */
	private calculateSeverityCounts(alerts: ScamAlert[]) {
		return {
			criticalCount: alerts.filter(
				(a) => a.severity === ScamSeverity.CRITICAL,
			).length,
			highCount: alerts.filter((a) => a.severity === ScamSeverity.HIGH)
				.length,
			mediumCount: alerts.filter((a) => a.severity === ScamSeverity.MEDIUM)
				.length,
			lowCount: alerts.filter((a) => a.severity === ScamSeverity.LOW).length,
		};
	}

	/**
	 * Calculate overall risk score (0-100)
	 */
	private calculateRiskScore(counts: {
		criticalCount: number;
		highCount: number;
		mediumCount: number;
		lowCount: number;
	}): number {
		const score =
			counts.criticalCount * 40 +
			counts.highCount * 25 +
			counts.mediumCount * 15 +
			counts.lowCount * 5;

		return Math.min(score, 100); // Cap at 100
	}
}
