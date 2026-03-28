import { Injectable, Logger } from "@nestjs/common";
import { HorizonService } from "../transactions/horizon.service";
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
	EXTERNAL_BLOCKLIST_SOURCES,
	ACCOUNT_AGE_THRESHOLDS,
	FREQUENCY_THRESHOLD,
} from "./constants/scam-rules.constants";
import type {
	PaymentLinkData,
	ScanResult,
	ScamAlert,
} from "./types/scam-alert.types";

type ScamRule = (linkData: PaymentLinkData) => Promise<ScamAlert[]>;

@Injectable()
export class ScamAlertsService {
	private readonly logger = new Logger(ScamAlertsService.name);

	// Cache for external blocklist checks (in-memory for simplicity, could be Redis in prod)
	private readonly blocklistCache = new Map<string, { data: string[]; timestamp: number }>();
	private readonly blocklistCacheTtl = 5 * 60 * 1000; // 5 minutes

	// Cache for account age checks (to avoid repeated API calls)
	private readonly accountAgeCache = new Map<string, { isRecent: boolean; timestamp: number }>();
	private readonly accountAgeCacheTtl = 10 * 60 * 1000; // 10 minutes

	constructor(private readonly horizonService: HorizonService) {}

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
		this.checkNewlyCreatedAccount.bind(this),
		this.checkHighFrequencyLowValuePattern.bind(this),
		this.checkExternalBlocklists.bind(this),
	];

	/**
	 * Scan a payment link for scam indicators
	 */
	async scanLink(linkData: PaymentLinkData): Promise<ScanResult> {
		this.logger.log(`Scanning link: ${JSON.stringify(linkData)}`);

		let alerts: ScamAlert[] = [];

		// Execute rule engine
		for (const rule of this.rules) {
			try {
				const ruleAlerts = await rule(linkData);
				alerts.push(...ruleAlerts);
			} catch (error) {
				this.logger.warn(`Error in scam rule: ${error.message}`);
				// Continue with other rules even if one fails
			}
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
	private checkMissingMemo(linkData: PaymentLinkData): Promise<ScamAlert[]> {
		if (
			ASSETS_REQUIRING_MEMO.includes(linkData.assetCode.toUpperCase()) &&
			!linkData.memo
		) {
			return Promise.resolve([
				{
					...SCAM_RULES[ScamAlertType.MISSING_MEMO],
					type: ScamAlertType.MISSING_MEMO,
				},
			]);
		}
		return Promise.resolve([]);
	}

	/**
	 * Check if amount is suspiciously high
	 */
	private checkHighAmount(linkData: PaymentLinkData): Promise<ScamAlert[]> {
		const maxAmount =
			MAX_REASONABLE_AMOUNTS[linkData.assetCode.toUpperCase()] ||
			MAX_REASONABLE_AMOUNTS.DEFAULT;

		if (linkData.amount > maxAmount) {
			return Promise.resolve([
				{
					...SCAM_RULES[ScamAlertType.HIGH_AMOUNT],
					type: ScamAlertType.HIGH_AMOUNT,
				},
			]);
		}
		return Promise.resolve([]);
	}

	/**
	 * Check if asset is not whitelisted
	 */
	private checkUnknownAsset(linkData: PaymentLinkData): Promise<ScamAlert[]> {
		if (!WHITELISTED_ASSETS.includes(linkData.assetCode.toUpperCase())) {
			return Promise.resolve([
				{
					...SCAM_RULES[ScamAlertType.UNKNOWN_ASSET],
					type: ScamAlertType.UNKNOWN_ASSET,
				},
			]);
		}
		return Promise.resolve([]);
	}

	/**
	 * Check for suspicious patterns in memo
	 */
	private checkSuspiciousMemo(linkData: PaymentLinkData): Promise<ScamAlert[]> {
		if (!linkData.memo) return Promise.resolve([]);

		const alerts: ScamAlert[] = [];

		// Check for external addresses in memo
		if (/G[A-Z0-9]{55}|0x[a-fA-F0-9]{40}/.test(linkData.memo)) {
			alerts.push({
				...SCAM_RULES[ScamAlertType.EXTERNAL_ADDRESS_IN_MEMO],
				type: ScamAlertType.EXTERNAL_ADDRESS_IN_MEMO,
			});
			// Critical alert, we can stop here for memo checks or return multiple?
			// The original implementation returned early. Let's return early if critical found to avoid noise.
			return Promise.resolve(alerts);
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

		return Promise.resolve(alerts);
	}

	/**
	 * Check if recipient is blacklisted
	 */
	private checkBlacklistedRecipient(linkData: PaymentLinkData): Promise<ScamAlert[]> {
		if (
			linkData.recipientAddress &&
			BLACKLISTED_RECIPIENTS.includes(linkData.recipientAddress)
		) {
			return Promise.resolve([
				{
					...SCAM_RULES[ScamAlertType.BLACKLISTED_RECIPIENT],
					type: ScamAlertType.BLACKLISTED_RECIPIENT,
				},
			]);
		}
		// Also check via regex if any blacklist term is in memo? Not required by strict interpretation but good practice.
		// Issue says "Blacklisted domains or usernames". Usually username is recipient.
		// If recipientAddress is username...
		return Promise.resolve([]);
	}

	/**
	 * Check if high value transfer is missing a memo
	 */
	private checkHighValueMissingMemo(linkData: PaymentLinkData): Promise<ScamAlert[]> {
		if (linkData.memo) return Promise.resolve([]);

		const threshold =
			HIGH_VALUE_THRESHOLDS[linkData.assetCode.toUpperCase()] ||
			HIGH_VALUE_THRESHOLDS.DEFAULT;

		if (linkData.amount >= threshold) {
			return Promise.resolve([
				{
					...SCAM_RULES[ScamAlertType.HIGH_VALUE_MISSING_MEMO],
					type: ScamAlertType.HIGH_VALUE_MISSING_MEMO,
				},
			]);
		}
		return Promise.resolve([]);
	}

	/**
	 * Check if recipient account was created recently
	 */
	private async checkNewlyCreatedAccount(linkData: PaymentLinkData): Promise<ScamAlert[]> {
		if (!linkData.recipientAddress) {
			return [];
		}

		// Check cache first
		const cached = this.accountAgeCache.get(linkData.recipientAddress);
		if (cached && (Date.now() - cached.timestamp) < this.accountAgeCacheTtl) {
			if (cached.isRecent) {
				return [
					{
						...SCAM_RULES[ScamAlertType.NEWLY_CREATED_ACCOUNT],
						type: ScamAlertType.NEWLY_CREATED_ACCOUNT,
					},
				];
			}
			return [];
		}

		try {
			// Use the existing HorizonService to get account info
			const horizonUrl = process.env.NETWORK === 'mainnet'
				? 'https://horizon.stellar.org'
				: 'https://horizon-testnet.stellar.org';
				
			const response = await fetch(`${horizonUrl}/accounts/${linkData.recipientAddress}`);
			
			if (!response.ok) {
				throw new Error(`Horizon API returned status ${response.status}`);
			}
			
			const accountData = await response.json();
			
			if (accountData && accountData.created_at) {
				const creationDate = new Date(accountData.created_at);
				const now = new Date();
				const ageInDays = (now.getTime() - creationDate.getTime()) / (1000 * 60 * 60 * 24);

				const isRecent = ageInDays <= ACCOUNT_AGE_THRESHOLDS.NEW_ACCOUNT_DAYS;
				
				// Cache the result
				this.accountAgeCache.set(linkData.recipientAddress, {
					isRecent,
					timestamp: Date.now()
				});

				if (isRecent) {
					return [
						{
							...SCAM_RULES[ScamAlertType.NEWLY_CREATED_ACCOUNT],
							type: ScamAlertType.NEWLY_CREATED_ACCOUNT,
						},
					];
				}
			}
		} catch (error) {
			// If we can't check the account age, log and continue
			this.logger.warn(`Could not check account age for ${linkData.recipientAddress}: ${error.message}`);
		}

		// Cache as not recent if we couldn't determine
		this.accountAgeCache.set(linkData.recipientAddress, {
			isRecent: false,
			timestamp: Date.now()
		});

		return [];
	}

	/**
	 * Check for high frequency/low value spam patterns
	 */
	private async checkHighFrequencyLowValuePattern(linkData: PaymentLinkData): Promise<ScamAlert[]> {
		if (!linkData.recipientAddress) {
			return [];
		}

		try {
			// Calculate time window for checking frequency
			const timeWindowMs = FREQUENCY_THRESHOLD.TIME_WINDOW_HOURS * 60 * 60 * 1000;
			const cutoffDate = new Date(Date.now() - timeWindowMs);
			const cutoffTimeString = cutoffDate.toISOString();

			// Fetch recent payments to the recipient using Horizon API
			const horizonUrl = process.env.NETWORK === 'mainnet'
				? 'https://horizon.stellar.org'
				: 'https://horizon-testnet.stellar.org';
				
			const response = await fetch(
				`${horizonUrl}/accounts/${linkData.recipientAddress}/payments` +
				`?limit=100&order=desc&created_at:gt=${encodeURIComponent(cutoffTimeString)}`
			);
			
			if (!response.ok) {
				throw new Error(`Horizon API returned status ${response.status}`);
			}
			
			const data = await response.json();
			const payments = data._embedded?.records || [];
			
			// Count payments that are below the low value threshold
			let lowValuePaymentCount = 0;
			for (const payment of payments) {
				if (payment.type === 'payment' && payment.amount) {
					// Convert to numeric value - assuming XLM as default
					let amountValue = parseFloat(payment.amount);
					
					// If it's a non-native asset, we might need to estimate value differently
					if (payment.asset_type !== 'native') {
						// For simplicity, we'll use the raw amount but in a real system, 
						// we'd convert to USD equivalent
						amountValue = parseFloat(payment.amount);
					}
					
					if (amountValue <= FREQUENCY_THRESHOLD.LOW_VALUE_THRESHOLD) {
						lowValuePaymentCount++;
					}
				}
			}
			
			// If we have more than the threshold of low-value payments in the time window
			if (lowValuePaymentCount >= FREQUENCY_THRESHOLD.HIGH_FREQUENCY_THRESHOLD) {
				return [
					{
						...SCAM_RULES[ScamAlertType.HIGH_FREQUENCY_LOW_VALUE],
						type: ScamAlertType.HIGH_FREQUENCY_LOW_VALUE,
					},
				];
			}
		} catch (error) {
			// If we can't check the transaction history, log and continue
			this.logger.warn(`Could not check frequency pattern for ${linkData.recipientAddress}: ${error.message}`);
		}

		return [];
	}

	/**
	 * Check against external blocklists
	 */
	private async checkExternalBlocklists(linkData: PaymentLinkData): Promise<ScamAlert[]> {
		if (!linkData.recipientAddress) {
			return [];
		}

		// Check cache first
		const cacheKey = `blocklist_${linkData.recipientAddress}`;
		const cached = this.blocklistCache.get(cacheKey);
		if (cached && (Date.now() - cached.timestamp) < this.blocklistCacheTtl) {
			if (cached.data.includes(linkData.recipientAddress)) {
				return [
					{
						...SCAM_RULES[ScamAlertType.BLACKLISTED_EXTERNAL],
						type: ScamAlertType.BLACKLISTED_EXTERNAL,
					},
				];
			}
			return [];
		}

		const alerts: ScamAlert[] = [];

		// Check each external blocklist source
		for (const source of EXTERNAL_BLOCKLIST_SOURCES) {
			try {
				const response = await fetch(source.url);
				
				if (!response.ok) {
					throw new Error(`Blocklist API returned status ${response.status}`);
				}
				
				const blocklistData = await response.json();
				
				if (Array.isArray(blocklistData)) {
					const blocklistAddresses = blocklistData as string[];
					
					if (blocklistAddresses.includes(linkData.recipientAddress)) {
						// Cache the result
						this.blocklistCache.set(cacheKey, {
							data: blocklistAddresses,
							timestamp: Date.now()
						});

						alerts.push({
							...SCAM_RULES[ScamAlertType.BLACKLISTED_EXTERNAL],
							type: ScamAlertType.BLACKLISTED_EXTERNAL,
						});
						
						// Break early since this is a critical alert
						break;
					} else {
						// Still cache the blocklist for this source
						this.blocklistCache.set(cacheKey, {
							data: blocklistAddresses,
							timestamp: Date.now()
						});
					}
				}
			} catch (error) {
				this.logger.warn(`Could not fetch external blocklist from ${source.name}: ${error.message}`);
				// Continue to next source
			}
		}

		return alerts;
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