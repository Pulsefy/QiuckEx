import { Test, TestingModule } from "@nestjs/testing";
import { ScamAlertsService } from "./scam-alerts.service";
import { ScamAlertType, ScamSeverity } from "./constants/scam-rules.constants";

describe("ScamAlertsService", () => {
	let service: ScamAlertsService;

	beforeEach(async () => {
		const module: TestingModule = await Test.createTestingModule({
			providers: [ScamAlertsService],
		}).compile();

		service = module.get<ScamAlertsService>(ScamAlertsService);
	});

	it("should be defined", () => {
		expect(service).toBeDefined();
	});

	describe("Missing Memo Detection", () => {
		it("should flag missing memo for USDC", () => {
			const result = service.scanLink({
				assetCode: "USDC",
				amount: 100,
				// No memo
			});

			expect(result.alerts).toHaveLength(1);
			expect(result.alerts[0].type).toBe(ScamAlertType.MISSING_MEMO);
			expect(result.alerts[0].severity).toBe(ScamSeverity.MEDIUM);
		});

		it("should not flag when memo is provided", () => {
			const result = service.scanLink({
				assetCode: "USDC",
				amount: 100,
				memo: "Invoice-123",
			});

			const memoAlerts = result.alerts.filter(
				(a) => a.type === ScamAlertType.MISSING_MEMO,
			);
			expect(memoAlerts).toHaveLength(0);
		});
	});

	describe("High Amount Detection", () => {
		it("should flag extremely high amounts", () => {
			const result = service.scanLink({
				assetCode: "USDC",
				amount: 200000, // Over $100k threshold
				memo: "test",
			});

			const highAmountAlert = result.alerts.find(
				(a) => a.type === ScamAlertType.HIGH_AMOUNT,
			);
			expect(highAmountAlert).toBeDefined();
			expect(highAmountAlert?.severity).toBe(ScamSeverity.HIGH);
		});

		it("should not flag reasonable amounts", () => {
			const result = service.scanLink({
				assetCode: "USDC",
				amount: 500,
				memo: "test",
			});

			const highAmountAlert = result.alerts.find(
				(a) => a.type === ScamAlertType.HIGH_AMOUNT,
			);
			expect(highAmountAlert).toBeUndefined();
		});
	});

	describe("Unknown Asset Detection", () => {
		it("should flag unknown assets", () => {
			const result = service.scanLink({
				assetCode: "SCAMCOIN",
				amount: 100,
				memo: "test",
			});

			const unknownAssetAlert = result.alerts.find(
				(a) => a.type === ScamAlertType.UNKNOWN_ASSET,
			);
			expect(unknownAssetAlert).toBeDefined();
			expect(unknownAssetAlert?.severity).toBe(ScamSeverity.MEDIUM);
		});

		it("should not flag whitelisted assets", () => {
			const result = service.scanLink({
				assetCode: "XLM",
				amount: 100,
				memo: "test",
			});

			const unknownAssetAlert = result.alerts.find(
				(a) => a.type === ScamAlertType.UNKNOWN_ASSET,
			);
			expect(unknownAssetAlert).toBeUndefined();
		});
	});

	describe("Suspicious Memo Patterns", () => {
		it("should detect external address in memo", () => {
			const result = service.scanLink({
				assetCode: "XLM",
				amount: 100,
				memo: "Send to GABC123DEFG456HIJK789LMNO012PQRS345TUVW678XYZA901BCDE234",
			});

			const addressAlert = result.alerts.find(
				(a) => a.type === ScamAlertType.EXTERNAL_ADDRESS_IN_MEMO,
			);
			expect(addressAlert).toBeDefined();
			expect(addressAlert?.severity).toBe(ScamSeverity.CRITICAL);
		});

		it("should detect urgency patterns", () => {
			const result = service.scanLink({
				assetCode: "XLM",
				amount: 100,
				memo: "URGENT: Send immediately!",
			});

			const urgencyAlert = result.alerts.find(
				(a) => a.type === ScamAlertType.URGENCY_PATTERN,
			);
			expect(urgencyAlert).toBeDefined();
			expect(urgencyAlert?.severity).toBe(ScamSeverity.HIGH);
		});

		it("should detect suspicious transfer patterns", () => {
			const result = service.scanLink({
				assetCode: "XLM",
				amount: 100,
				memo: "transfer to wallet address",
			});

			const suspiciousAlert = result.alerts.find(
				(a) => a.type === ScamAlertType.SUSPICIOUS_MEMO,
			);
			expect(suspiciousAlert).toBeDefined();
		});

		it("should not flag safe memos", () => {
			const result = service.scanLink({
				assetCode: "XLM",
				amount: 100,
				memo: "Invoice-12345",
			});

			const suspiciousAlerts = result.alerts.filter(
				(a) =>
					a.type === ScamAlertType.SUSPICIOUS_MEMO ||
					a.type === ScamAlertType.EXTERNAL_ADDRESS_IN_MEMO ||
					a.type === ScamAlertType.URGENCY_PATTERN,
			);
			expect(suspiciousAlerts).toHaveLength(0);
		});
	});

	describe("Risk Score Calculation", () => {
		it("should calculate risk score correctly", () => {
			const result = service.scanLink({
				assetCode: "SCAMCOIN",
				amount: 200000,
				memo: "URGENT: Send to GABC123DEFG456HIJK789LMNO012PQRS345TUVW678XYZA901BCDE234",
			});

			expect(result.riskScore).toBeGreaterThan(50);
			expect(result.isSafe).toBe(false);
		});

		it("should mark safe links as safe", () => {
			const result = service.scanLink({
				assetCode: "XLM",
				amount: 100,
				memo: "Payment for services",
			});

			expect(result.riskScore).toBeLessThan(50);
			expect(result.isSafe).toBe(true);
		});
	});

	describe("Multiple Alerts", () => {
		it("should detect multiple issues", () => {
			const result = service.scanLink({
				assetCode: "USDC",
				amount: 200000,
			});

			expect(result.alerts.length).toBeGreaterThan(1);
			expect(result.alerts).toEqual(
				expect.arrayContaining([
					expect.objectContaining({ type: ScamAlertType.MISSING_MEMO }), // Changed
					expect.objectContaining({ type: ScamAlertType.HIGH_AMOUNT }),
				]),
			);
		});
	});

	describe("Severity Counts", () => {
		it("should count severities correctly", () => {
			const result = service.scanLink({
				assetCode: "USDC",
				amount: 200000, // Add high amount to get HIGH severity
				memo: "Send to GABC123DEFG456HIJK789LMNO012PQRS345TUVW678XYZA901BCDE234",
			});

			expect(result.criticalCount).toBeGreaterThan(0);
			expect(result.highCount).toBeGreaterThan(0);
			expect(
				result.criticalCount +
				result.highCount +
				result.mediumCount +
				result.lowCount,
			).toBe(result.alerts.length);
		});
	});


	describe("Blacklisted Recipient Detection", () => {
		it("should flag blacklisted recipients", () => {
			const result = service.scanLink({
				assetCode: "USDC",
				amount: 100,
				recipientAddress: "G123456789ABCDEF",
				memo: "test",
			});

			const blacklistAlert = result.alerts.find(
				(a) => a.type === ScamAlertType.BLACKLISTED_RECIPIENT,
			);
			expect(blacklistAlert).toBeDefined();
			expect(blacklistAlert?.severity).toBe(ScamSeverity.CRITICAL);
		});
	});

	describe("High Value Missing Memo Detection", () => {
		it("should flag high value transfers without memo", () => {
			// USDC threshold is 1000
			const result = service.scanLink({
				assetCode: "USDC",
				amount: 2000,
				// No memo
			});

			const highValueAlert = result.alerts.find(
				(a) => a.type === ScamAlertType.HIGH_VALUE_MISSING_MEMO,
			);
			expect(highValueAlert).toBeDefined();
			expect(highValueAlert?.severity).toBe(ScamSeverity.HIGH);
		});

		it("should not flag high value transfers with memo", () => {
			const result = service.scanLink({
				assetCode: "USDC",
				amount: 2000,
				memo: "Invoice",
			});

			const highValueAlert = result.alerts.find(
				(a) => a.type === ScamAlertType.HIGH_VALUE_MISSING_MEMO,
			);
			expect(highValueAlert).toBeUndefined();
		});
	});
});
