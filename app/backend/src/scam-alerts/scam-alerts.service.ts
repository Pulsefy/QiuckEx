import { Injectable, Logger } from "@nestjs/common";
import {
	ASSETS_REQUIRING_MEMO,
	WHITELISTED_ASSETS,
	MAX_REASONABLE_AMOUNTS,
	HIGH_VALUE_THRESHOLDS,
	SUSPICIOUS_MEMO_PATTERNS,
	BLACKLISTED_RECIPIENTS,
	SCAM_RULES,
	ScamAlertType,
	ScamSeverity,
} from "./constants/scam-rules.constants";
import type {
	PaymentLinkData,
	ScanResult,
	ScamAlert,
} from "./types/scam-alert.types";

type ScamRule = (linkData: PaymentLinkData) => ScamAlert[];

@Injectable()
export class ScamAlertsService {
	private readonly logger = new Logger(ScamAlertsService.name);

	/**
	 * List of active scam detection rules
	 */
	private readonly rules: ScamRule[] = [
		this.checkMissingMemo.bind(this),
		this.checkHighAmount.bind(this),
		this.checkUnknownAsset.bind(this),
		this.checkSuspiciousMemo.bind(this),
		this.checkBlacklistedRecipient.bind(this),
		this.checkHighValueMissingMemo.bind(this),
	];

	/**
	 * Scan a payment link for scam indicators
	 */
	scanLink(linkData: PaymentLinkData): ScanResult {
		this.logger.log(`Scanning link: ${JSON.stringify(linkData)}`);

		const alerts: ScamAlert[] = [];

		// Execute rule engine
		for (const rule of this.rules) {
			alerts.push(...rule(linkData));
		}

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
	private checkMissingMemo(linkData: PaymentLinkData): ScamAlert[] {
		if (
			ASSETS_REQUIRING_MEMO.includes(linkData.assetCode.toUpperCase()) &&
			!linkData.memo
		) {
			return [
				{
					...SCAM_RULES[ScamAlertType.MISSING_MEMO],
					type: ScamAlertType.MISSING_MEMO,
				},
			];
		}
		return [];
	}

	/**
	 * Check if amount is suspiciously high
	 */
	private checkHighAmount(linkData: PaymentLinkData): ScamAlert[] {
		const maxAmount =
			MAX_REASONABLE_AMOUNTS[linkData.assetCode.toUpperCase()] ||
			MAX_REASONABLE_AMOUNTS.DEFAULT;

		if (linkData.amount > maxAmount) {
			return [
				{
					...SCAM_RULES[ScamAlertType.HIGH_AMOUNT],
					type: ScamAlertType.HIGH_AMOUNT,
				},
			];
		}
		return [];
	}

	/**
	 * Check if asset is not whitelisted
	 */
	private checkUnknownAsset(linkData: PaymentLinkData): ScamAlert[] {
		if (!WHITELISTED_ASSETS.includes(linkData.assetCode.toUpperCase())) {
			return [
				{
					...SCAM_RULES[ScamAlertType.UNKNOWN_ASSET],
					type: ScamAlertType.UNKNOWN_ASSET,
				},
			];
		}
		return [];
	}

	/**
	 * Check for suspicious patterns in memo
	 */
	private checkSuspiciousMemo(linkData: PaymentLinkData): ScamAlert[] {
		if (!linkData.memo) return [];

		const alerts: ScamAlert[] = [];

		// Check for external addresses in memo
		if (/G[A-Z0-9]{55}|0x[a-fA-F0-9]{40}/.test(linkData.memo)) {
			alerts.push({
				...SCAM_RULES[ScamAlertType.EXTERNAL_ADDRESS_IN_MEMO],
				type: ScamAlertType.EXTERNAL_ADDRESS_IN_MEMO,
			});
			// Critical alert, we can stop here for memo checks or return multiple?
			// The original implementation returned early. Let's return early if critical found to avoid noise.
			return alerts;
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
				break; // Only add once per pattern set
			}
		}

		return alerts;
	}

	/**
	 * Check if recipient is blacklisted
	 */
	private checkBlacklistedRecipient(linkData: PaymentLinkData): ScamAlert[] {
		if (
			linkData.recipientAddress &&
			BLACKLISTED_RECIPIENTS.includes(linkData.recipientAddress)
		) {
			return [
				{
					...SCAM_RULES[ScamAlertType.BLACKLISTED_RECIPIENT],
					type: ScamAlertType.BLACKLISTED_RECIPIENT,
				},
			];
		}
		// Also check via regex if any blacklist term is in memo? Not required by strict interpretation but good practice.
		// Issue says "Blacklisted domains or usernames". Usually username is recipient.
		// If recipientAddress is username...
		return [];
	}

	/**
	 * Check if high value transfer is missing a memo
	 */
	private checkHighValueMissingMemo(linkData: PaymentLinkData): ScamAlert[] {
		if (linkData.memo) return [];

		const threshold =
			HIGH_VALUE_THRESHOLDS[linkData.assetCode.toUpperCase()] ||
			HIGH_VALUE_THRESHOLDS.DEFAULT;

		if (linkData.amount >= threshold) {
			return [
				{
					...SCAM_RULES[ScamAlertType.HIGH_VALUE_MISSING_MEMO],
					type: ScamAlertType.HIGH_VALUE_MISSING_MEMO,
				},
			];
		}
		return [];
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
