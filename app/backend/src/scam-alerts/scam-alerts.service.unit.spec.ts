import { Test, TestingModule } from "@nestjs/testing";
import { ScamAlertsService } from "./scam-alerts.service";
import {
	ScamAlertType,
	ScamSeverity,
	EXTERNAL_BLOCKLIST_SOURCES,
} from "./constants/scam-rules.constants";
import { HorizonService } from "../transactions/horizon.service";
import { AppConfigService } from "../config";

// Define a type that represents the internal structure of the service for testing
type InternalScamAlertsService = {
  accountAgeCache: Map<string, { isRecent: boolean; timestamp: number }>;
  blocklistCache: Map<string, { data: string[]; timestamp: number }>;
};

// Mock fetch globally for the tests (only blocklist sources use it now;
// Horizon calls go through the mocked HorizonService).
global.fetch = jest.fn();

const mockHorizonService = {
  getAccount: jest.fn(),
  getPaymentsSince: jest.fn(),
};

const mockConfigService = {
  // Small enough to keep the timeout tests fast, large enough to stay stable.
  scamAlertsFetchTimeoutMs: 150,
};

describe("ScamAlertsService", () => {
	let service: ScamAlertsService;

	beforeEach(async () => {
		const module: TestingModule = await Test.createTestingModule({
			providers: [
				ScamAlertsService,
				{
					provide: HorizonService,
					useValue: mockHorizonService,
				},
				{
					provide: AppConfigService,
					useValue: mockConfigService,
				},
			],
		}).compile();

		service = module.get<ScamAlertsService>(ScamAlertsService);

		// Reset fetch mock with a harmless default response
		(global.fetch as jest.MockedFunction<typeof fetch>)
			.mockReset()
			.mockResolvedValue({
				ok: true,
				status: 200,
				json: async () => [],
			} as Response);
		mockHorizonService.getAccount.mockReset().mockResolvedValue(null);
		mockHorizonService.getPaymentsSince.mockReset().mockResolvedValue([]);
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
			// Clear the cache before each test using a properly typed cast
			(service as unknown as InternalScamAlertsService).accountAgeCache.clear();
		});

		it("should flag newly created accounts", async () => {
			// Account lookup goes through HorizonService
			mockHorizonService.getAccount.mockResolvedValue({
				created_at: new Date(Date.now() - 2 * 24 * 60 * 60 * 1000).toISOString(), // 2 days ago
			});

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
			expect(mockHorizonService.getAccount).toHaveBeenCalledWith(
				"GNEWLYCREATEDACCOUNTHASBEENREGISTEREDRECENTLY123456789",
			);
		});

		it("should not flag older accounts", async () => {
			// Account lookup goes through HorizonService
			mockHorizonService.getAccount.mockResolvedValue({
				created_at: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString(), // 30 days ago
			});

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
			// Clear the cache before each test using a properly typed cast
			(service as unknown as InternalScamAlertsService).blocklistCache.clear();
		});

		it("should flag addresses on external blocklist", async () => {
			(global.fetch as jest.MockedFunction<typeof fetch>).mockResolvedValue({
				ok: true,
				status: 200,
				json: async () => [
					"GBLACKLISTEDADDRESS123456789",
					"GANOTHERBLACKLISTEDADDR456789",
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
				// Mock fetch responses used by account age/frequency/blocklist checks
			(global.fetch as jest.MockedFunction<typeof fetch>)
				.mockResolvedValue({
					ok: true,
					status: 200,
						json: async () => ({ _embedded: { records: [] } }),
				} as Response);

			const result = await service.scanLink({
				assetCode: "USDC",
				amount: 200000,
				memo: "Send to GABC123DEFG456HIJK789LMNO012PQRS345TUVW678XYZA901BCDE234 urgently",
			});

			expect(result.alerts.length).toBeGreaterThan(1);
			expect(result.alerts).toEqual(
				expect.arrayContaining([
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

	describe("Horizon checks via HorizonService", () => {
		const recipient = "GRECIPIENTACCOUNT123456789ABCDEFGHIJKLMNO";

		it("performs account and payment checks through HorizonService, not raw fetch", async () => {
			mockHorizonService.getAccount.mockResolvedValue({
				created_at: new Date(
					Date.now() - 30 * 24 * 60 * 60 * 1000,
				).toISOString(),
			});

			const result = await service.scanLink({
				assetCode: "USDC",
				amount: 100,
				memo: "test",
				recipientAddress: recipient,
			});

			expect(result).toBeDefined();
			expect(mockHorizonService.getAccount).toHaveBeenCalledWith(recipient);
			expect(mockHorizonService.getPaymentsSince).toHaveBeenCalledTimes(1);

			const [accountId, sinceIso, limit] =
				mockHorizonService.getPaymentsSince.mock.calls[0];
			expect(accountId).toBe(recipient);
			expect(limit).toBe(100);
			// The cutoff sits inside the trailing one-hour window
			const windowAgeMs = Date.now() - Date.parse(sinceIso as string);
			expect(windowAgeMs).toBeGreaterThanOrEqual(60 * 60 * 1000 - 5000);
			expect(windowAgeMs).toBeLessThanOrEqual(60 * 60 * 1000 + 5000);

			// Any direct fetch is confined to the configured blocklist sources
			const blocklistUrls = EXTERNAL_BLOCKLIST_SOURCES.map((s) => s.url);
			const fetchCalls = (global.fetch as jest.MockedFunction<typeof fetch>)
				.mock.calls;
			expect(fetchCalls.length).toBeGreaterThan(0);
			for (const call of fetchCalls) {
				expect(blocklistUrls).toContain(String(call[0]));
			}
		});

		it("flags high-frequency low-value patterns from HorizonService payments", async () => {
			mockHorizonService.getPaymentsSince.mockResolvedValue(
				Array.from({ length: 5 }, () => ({
					type: "payment",
					amount: "1.0",
					asset_type: "native",
					created_at: new Date().toISOString(),
				})),
			);

			const result = await service.scanLink({
				assetCode: "USDC",
				amount: 100,
				memo: "test",
				recipientAddress: recipient,
			});

			const frequencyAlert = result.alerts.find(
				(a) => a.type === ScamAlertType.HIGH_FREQUENCY_LOW_VALUE,
			);
			expect(frequencyAlert).toBeDefined();
			expect(frequencyAlert?.severity).toBe(ScamSeverity.HIGH);
		});
	});

	describe("Horizon failure handling", () => {
		it("treats Horizon failures as no signal and still completes the scan", async () => {
			mockHorizonService.getAccount.mockRejectedValue(
				new Error("Horizon request timed out after 10000ms"),
			);
			mockHorizonService.getPaymentsSince.mockRejectedValue(
				new Error(
					"Horizon service temporarily unavailable. Please try again later.",
				),
			);

			const result = await service.scanLink({
				assetCode: "USDC",
				amount: 100,
				// No memo: proves the local rules still ran
				recipientAddress: "GFAILUREHANDLINGRECIPIENT123456789ABCDEFGHI",
			});

			expect(
				result.alerts.find(
					(a) => a.type === ScamAlertType.NEWLY_CREATED_ACCOUNT,
				),
			).toBeUndefined();
			expect(
				result.alerts.find(
					(a) => a.type === ScamAlertType.HIGH_FREQUENCY_LOW_VALUE,
				),
			).toBeUndefined();
			expect(
				result.alerts.find((a) => a.type === ScamAlertType.MISSING_MEMO),
			).toBeDefined();
		});
	});

	describe("External timeout handling", () => {
		beforeEach(() => {
			// Clear the cache before each test using a properly typed cast
			(service as unknown as InternalScamAlertsService).blocklistCache.clear();
		});

		it("completes the scan within the timeout budget when blocklist endpoints hang", async () => {
			const timeoutMs = mockConfigService.scamAlertsFetchTimeoutMs;
			let inFlight = 0;
			let maxInFlight = 0;
			(global.fetch as jest.MockedFunction<typeof fetch>).mockImplementation(
				(_input: RequestInfo | URL, init?: RequestInit) => {
					inFlight++;
					maxInFlight = Math.max(maxInFlight, inFlight);
					return new Promise<Response>((_resolve, reject) => {
						init?.signal?.addEventListener("abort", () => {
							inFlight--;
							reject(
								new DOMException("This operation was aborted", "AbortError"),
							);
						});
					});
				},
			);

			const startedAt = Date.now();
			const result = await service.scanLink({
				assetCode: "USDC",
				amount: 100,
				memo: "test",
				recipientAddress: "GHANGINGBLOCKLISTRECIPIENT123456789ABCDEF",
			});
			const elapsedMs = Date.now() - startedAt;

			expect(
				result.alerts.find(
					(a) => a.type === ScamAlertType.BLACKLISTED_EXTERNAL,
				),
			).toBeUndefined();
			expect(elapsedMs).toBeLessThan(timeoutMs + 1000);
			// Every source was in flight at once: a hanging source did not delay
			// the others.
			expect(maxInFlight).toBe(EXTERNAL_BLOCKLIST_SOURCES.length);
		});

		it("keeps checking the other sources when one blocklist source fails", async () => {
			const flaggedRecipient = "GFLAGGEDBYSECONDSOURCE123456789ABCDEF";
			(global.fetch as jest.MockedFunction<typeof fetch>).mockImplementation(
				async (input: RequestInfo | URL) => {
					if (String(input) === EXTERNAL_BLOCKLIST_SOURCES[0].url) {
						throw new Error("connect ECONNREFUSED 127.0.0.1:1");
					}
					return {
						ok: true,
						status: 200,
						json: async () => [flaggedRecipient],
					} as Response;
				},
			);

			const result = await service.scanLink({
				assetCode: "USDC",
				amount: 100,
				memo: "test",
				recipientAddress: flaggedRecipient,
			});

			expect(
				result.alerts.find(
					(a) => a.type === ScamAlertType.BLACKLISTED_EXTERNAL,
				),
			).toBeDefined();
		});
	});
});