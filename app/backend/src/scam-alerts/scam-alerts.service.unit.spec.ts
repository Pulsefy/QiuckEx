import { Test, TestingModule } from "@nestjs/testing";
import { ScamAlertsService } from "./scam-alerts.service";
import { ScamAlertType, ScamSeverity } from "./constants/scam-rules.constants";

// Mock fetch globally for the tests
global.fetch = jest.fn();

describe("ScamAlertsService", () => {
	let service: ScamAlertsService;

	beforeEach(async () => {
		const module: TestingModule = await Test.createTestingModule({
			providers: [
				ScamAlertsService,
			],
		}).compile();

		service = module.get<ScamAlertsService>(ScamAlertsService);
		
		// Reset fetch mock
		(global.fetch as jest.MockedFunction<typeof fetch>).mockClear();
	});

	it("should be defined", () => {
		expect(service).toBeDefined();
	});

	describe("Missing Memo Detection", () => {
		it("should flag missing memo for USDC", async () => {
			const result = await service.scanLink({
				assetCode: "USDC",
				amount: 100,
				// No memo
			});

			expect(result.alerts).toHaveLength(1);
			expect(result.alerts[0].type).toBe(ScamAlertType.MISSING_MEMO);
			expect(result.alerts[0].severity).toBe(ScamSeverity.MEDIUM);
		});

		it("should not flag when memo is provided", async () => {
			const result = await service.scanLink({
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
		it("should flag extremely high amounts", async () => {
			const result = await service.scanLink({
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

		it("should not flag reasonable amounts", async () => {
			const result = await service.scanLink({
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
		it("should flag unknown assets", async () => {
			const result = await service.scanLink({
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

		it("should not flag whitelisted assets", async () => {
			const result = await service.scanLink({
				assetCode: "USDC",
				amount: 100,
				memo: "test",
			});

			const unknownAssetAlert = result.alerts.find(
				(a) => a.type === ScamAlertType.UNKNOWN_ASSET,
			);
			expect(unknownAssetAlert).toBeUndefined();
		});
	});

	describe("Suspicious Memo Detection", () => {
		it("should flag external addresses in memo", async () => {
			const result = await service.scanLink({
				assetCode: "USDC",
				amount: 100,
				memo: "Send to GABC123DEFG456HIJK789LMNO012PQRS345TUVW678XYZA901BCDE234",
			});

			const externalAddressAlert = result.alerts.find(
				(a) => a.type === ScamAlertType.EXTERNAL_ADDRESS_IN_MEMO,
			);
			expect(externalAddressAlert).toBeDefined();
			expect(externalAddressAlert?.severity).toBe(ScamSeverity.CRITICAL);
		});

		it("should flag urgency patterns", async () => {
			const result = await service.scanLink({
				assetCode: "USDC",
				amount: 100,
				memo: "URGENT PAYMENT ASAP",
			});

			const urgencyAlert = result.alerts.find(
				(a) => a.type === ScamAlertType.URGENCY_PATTERN,
			);
			expect(urgencyAlert).toBeDefined();
			expect(urgencyAlert?.severity).toBe(ScamSeverity.HIGH);
		});
	});

	describe("Newly Created Account Detection", () => {
		beforeEach(() => {
			// Clear the cache before each test
			(service as any).accountAgeCache.clear();
		});

		it("should flag newly created accounts", async () => {
			// Mock fetch response for a newly created account
			(global.fetch as jest.MockedFunction<typeof fetch>)
				.mockResolvedValueOnce({
					ok: true,
					status: 200,
					json: async () => ({
						created_at: new Date(Date.now() - 2 * 24 * 60 * 60 * 1000).toISOString(), // 2 days ago
					}),
				} as Response);

			const result = await service.scanLink({
				assetCode: "USDC",
				amount: 100,
				memo: "test",
				recipientAddress: "GNEWLYCREATEDACCOUNTHASBEENREGISTEREDRECENTLY123456789",
			});

			const newAccountAlert = result.alerts.find(
				(a) => a.type === ScamAlertType.NEWLY_CREATED_ACCOUNT,
			);
			expect(newAccountAlert).toBeDefined();
			expect(newAccountAlert?.severity).toBe(ScamSeverity.MEDIUM);
		});

		it("should not flag older accounts", async () => {
			// Mock fetch response for an older account
			(global.fetch as jest.MockedFunction<typeof fetch>)
				.mockResolvedValueOnce({
					ok: true,
					status: 200,
					json: async () => ({
						created_at: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString(), // 30 days ago
					}),
				} as Response);

			const result = await service.scanLink({
				assetCode: "USDC",
				amount: 100,
				memo: "test",
				recipientAddress: "GOLDERACCOUNTTHATWASCREATEDMANYDAYSAGO123456789",
			});

			const newAccountAlert = result.alerts.find(
				(a) => a.type === ScamAlertType.NEWLY_CREATED_ACCOUNT,
			);
			expect(newAccountAlert).toBeUndefined();
		});
	});

	describe("External Blocklist Detection", () => {
		beforeEach(() => {
			// Clear the cache before each test
			(service as any).blocklistCache.clear();
		});

		it("should flag addresses on external blocklist", async () => {
			// Mock fetch response for blocklist
			(global.fetch as jest.MockedFunction<typeof fetch>)
				.mockResolvedValueOnce({
					ok: true,
					status: 200,
					json: async () => [
						"GBLACKLISTEDADDRESS123456789",
						"GANOTHERBLACKLISTEDADDR456789"
					],
				} as Response);

			const result = await service.scanLink({
				assetCode: "USDC",
				amount: 100,
				memo: "test",
				recipientAddress: "GBLACKLISTEDADDRESS123456789",
			});

			const blocklistAlert = result.alerts.find(
				(a) => a.type === ScamAlertType.BLACKLISTED_EXTERNAL,
			);
			expect(blocklistAlert).toBeDefined();
			expect(blocklistAlert?.severity).toBe(ScamSeverity.CRITICAL);
		});

		it("should not flag addresses not on external blocklist", async () => {
			// Mock fetch response for blocklist
			(global.fetch as jest.MockedFunction<typeof fetch>)
				.mockResolvedValueOnce({
					ok: true,
					status: 200,
					json: async () => [
						"GDIFFERENTBLACKLISTEDADDR123456789",
						"GANOTHERBLACKLISTEDADDR456789"
					],
				} as Response);

			const result = await service.scanLink({
				assetCode: "USDC",
				amount: 100,
				memo: "test",
				recipientAddress: "GSAFEADDRESS123456789",
			});

			const blocklistAlert = result.alerts.find(
				(a) => a.type === ScamAlertType.BLACKLISTED_EXTERNAL,
			);
			expect(blocklistAlert).toBeUndefined();
		});
	});

	describe("Multiple Alerts", () => {
		it("should detect multiple issues", async () => {
			// Mock fetch responses for blocklist (but not for account age since we're not testing that here)
			(global.fetch as jest.MockedFunction<typeof fetch>)
				.mockResolvedValue({
					ok: true,
					status: 200,
					json: async () => [],
				} as Response);

			const result = await service.scanLink({
				assetCode: "USDC",
				amount: 200000,
				memo: "Send to GABC123DEFG456HIJK789LMNO012PQRS345TUVW678XYZA901BCDE234 urgently",
			});

			expect(result.alerts.length).toBeGreaterThan(1);
			expect(result.alerts).toEqual(
				expect.arrayContaining([
					expect.objectContaining({ type: ScamAlertType.MISSING_MEMO }),
					expect.objectContaining({ type: ScamAlertType.HIGH_AMOUNT }),
					expect.objectContaining({ type: ScamAlertType.EXTERNAL_ADDRESS_IN_MEMO }),
				]),
			);
		});
	});

	describe("Severity Counts", () => {
		it("should count severities correctly", async () => {
			// Mock fetch responses
			(global.fetch as jest.MockedFunction<typeof fetch>)
				.mockResolvedValue({
					ok: true,
					status: 200,
					json: async () => [],
				} as Response);

			const result = await service.scanLink({
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
		it("should flag blacklisted recipients", async () => {
			const result = await service.scanLink({
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
		it("should flag high value transfers without memo", async () => {
			// USDC threshold is 1000
			const result = await service.scanLink({
				assetCode: "USDC",
				amount: 2000,
				// No memo
			});

			const highValueMissingMemoAlert = result.alerts.find(
				(a) => a.type === ScamAlertType.HIGH_VALUE_MISSING_MEMO,
			);
			expect(highValueMissingMemoAlert).toBeDefined();
			expect(highValueMissingMemoAlert?.severity).toBe(ScamSeverity.HIGH);
		});

		it("should not flag low value transfers without memo", async () => {
			const result = await service.scanLink({
				assetCode: "USDC",
				amount: 100,
				// No memo
			});

			const highValueMissingMemoAlert = result.alerts.find(
				(a) => a.type === ScamAlertType.HIGH_VALUE_MISSING_MEMO,
			);
			expect(highValueMissingMemoAlert).toBeUndefined();
		});
	});
});