/**
 * Scam detection rules and thresholds
 * These constants define the heuristics used to detect suspicious payment links
 */

/**
 * Assets that require memo for identification
 */
export const ASSETS_REQUIRING_MEMO = [
	"USDC",
	"USDT",
	"XLM",
	"EUR",
	"NGN",
	"GBP",
];

/**
 * Whitelisted asset codes (known safe assets)
 */
export const WHITELISTED_ASSETS = [
	"XLM",
	"USDC",
	"USDT",
	"BTC",
	"ETH",
	"EURC",
	"AQUA",
	"yXLM",
];

/**
 * Maximum reasonable amounts for different asset types (in base units)
 */
export const MAX_REASONABLE_AMOUNTS = {
	XLM: 1000000, // 1 million XLM
	USDC: 100000, // $100k
	USDT: 100000, // $100k
	NGN: 50000000, // ₦50M
	DEFAULT: 1000000,
};

/**
 * Suspicious memo patterns (regex)
 */
export const SUSPICIOUS_MEMO_PATTERNS = [
	/send.*to.*address/i, // "send to address X"
	/transfer.*to.*wallet/i, // "transfer to wallet X"
	/deposit.*here/i, // "deposit here"
	/G[A-Z0-9]{55}/i, // Stellar address in memo
	/0x[a-fA-F0-9]{40}/i, // Ethereum address in memo
	/bitcoin.*address/i, // Bitcoin address reference
	/urgent.*transfer/i, // Urgency scam
	/verify.*account/i, // Verification scam
	/claim.*reward/i, // Reward scam
];

/**
 * Severity levels for scam alerts
 */
export enum ScamSeverity {
	LOW = "low",
	MEDIUM = "medium",
	HIGH = "high",
	CRITICAL = "critical",
}

/**
 * Scam alert types
 */
export enum ScamAlertType {
	MISSING_MEMO = "missing_memo",
	HIGH_AMOUNT = "high_amount",
	UNKNOWN_ASSET = "unknown_asset",
	SUSPICIOUS_MEMO = "suspicious_memo",
	EXTERNAL_ADDRESS_IN_MEMO = "external_address_in_memo",
	URGENCY_PATTERN = "urgency_pattern",
}

/**
 * Rule configurations with severity
 */
export const SCAM_RULES = {
	[ScamAlertType.MISSING_MEMO]: {
		severity: ScamSeverity.MEDIUM,
		message: "Payment link requires a memo but none is provided",
		recommendation: "Add a unique memo to identify your payment",
	},
	[ScamAlertType.HIGH_AMOUNT]: {
		severity: ScamSeverity.HIGH,
		message: "Payment amount exceeds reasonable threshold",
		recommendation: "Verify the amount with the recipient before proceeding",
	},
	[ScamAlertType.UNKNOWN_ASSET]: {
		severity: ScamSeverity.MEDIUM,
		message: "Asset code is not on the whitelist of known safe assets",
		recommendation: "Verify this is a legitimate asset before sending",
	},
	[ScamAlertType.SUSPICIOUS_MEMO]: {
		severity: ScamSeverity.CRITICAL,
		message: "Memo contains suspicious patterns often used in scams",
		recommendation: "Do NOT proceed. This looks like a scam attempt",
	},
	[ScamAlertType.EXTERNAL_ADDRESS_IN_MEMO]: {
		severity: ScamSeverity.CRITICAL,
		message: "Memo contains what appears to be an external wallet address",
		recommendation:
			"STOP! Never send funds to addresses in memos. This is a scam.",
	},
	[ScamAlertType.URGENCY_PATTERN]: {
		severity: ScamSeverity.HIGH,
		message: "Memo uses urgency tactics common in scam attempts",
		recommendation: "Take your time. Legitimate requests are never urgent.",
	},
};
