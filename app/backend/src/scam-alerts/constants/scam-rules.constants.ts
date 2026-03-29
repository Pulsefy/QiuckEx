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
 * Thresholds for "high value" transfers that should definitely have a memo
 */
export const HIGH_VALUE_THRESHOLDS = {
	XLM: 5000,
	USDC: 1000,
	USDT: 1000,
	DEFAULT: 5000,
};

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
 * Blacklisted domains, usernames, or addresses
 */
export const BLACKLISTED_RECIPIENTS = [
	"scammer.com",
	"phishing-site.net",
	"fake-exchange",
	"not-real-wallet",
	"G123456789ABCDEF", // Example blacklisted address
];

/**
 * External blocklist sources
 */
export const EXTERNAL_BLOCKLIST_SOURCES = [
	{
		name: "Stellar Expert Blocklist",
		url: "https://api.stellar.expert/api/blocklist",
		method: "GET"
	},
	{
		name: "QuickEx Community Blocklist",
		url: "https://blocklist.quickex.io/api/v1/blocklist",
		method: "GET"
	}
];

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
 * Thresholds for account age checks (in days)
 */
export const ACCOUNT_AGE_THRESHOLDS = {
	NEW_ACCOUNT_DAYS: 7, // Accounts younger than this are considered new
	MODERATE_ACCOUNT_DAYS: 30, // Accounts younger than this may trigger warnings
};

/**
 * Thresholds for frequency/amount patterns
 */
export const FREQUENCY_THRESHOLD = {
	LOW_VALUE_THRESHOLD: 10, // Amount under which frequency becomes suspicious (in USD equivalent)
	HIGH_FREQUENCY_THRESHOLD: 5, // Number of transactions in time window that triggers alert
	TIME_WINDOW_HOURS: 1, // Time window in hours to check for frequency
};

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
	BLACKLISTED_RECIPIENT = "blacklisted_recipient",
	HIGH_VALUE_MISSING_MEMO = "high_value_missing_memo",
	NEWLY_CREATED_ACCOUNT = "newly_created_account",
	HIGH_FREQUENCY_LOW_VALUE = "high_frequency_low_value",
	BLACKLISTED_EXTERNAL = "blacklisted_external",
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
	[ScamAlertType.BLACKLISTED_RECIPIENT]: {
		severity: ScamSeverity.CRITICAL,
		message: "Recipient is on a known blacklist",
		recommendation: "ABORT IMMEDIATELY. This recipient is known to be malicious.",
	},
	[ScamAlertType.HIGH_VALUE_MISSING_MEMO]: {
		severity: ScamSeverity.HIGH,
		message: "High value transfer missing a memo",
		recommendation:
			"Large transfers usually require a memo. Verify with the recipient.",
	},
	[ScamAlertType.NEWLY_CREATED_ACCOUNT]: {
		severity: ScamSeverity.MEDIUM,
		message: "Recipient account was created recently",
		recommendation: "Be cautious when sending to newly created accounts",
	},
	[ScamAlertType.HIGH_FREQUENCY_LOW_VALUE]: {
		severity: ScamSeverity.HIGH,
		message: "High frequency of low-value transactions may indicate spam",
		recommendation: "This pattern is common in spam/phishing attacks",
	},
	[ScamAlertType.BLACKLISTED_EXTERNAL]: {
		severity: ScamSeverity.CRITICAL,
		message: "Recipient is on an external blocklist",
		recommendation: "ABORT IMMEDIATELY. This recipient is flagged by external security sources.",
	},
};
