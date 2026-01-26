import { Test, TestingModule } from "@nestjs/testing";
import { ScamAlertsController } from "./scam-alerts.controller";
import { ScamAlertsService } from "./scam-alerts.service";

describe("ScamAlertsController", () => {
	let controller: ScamAlertsController;

	beforeEach(async () => {
		const module: TestingModule = await Test.createTestingModule({
			controllers: [ScamAlertsController],
			providers: [ScamAlertsService],
		}).compile();

		controller = module.get<ScamAlertsController>(ScamAlertsController);
	});

	it("should be defined", () => {
		expect(controller).toBeDefined();
	});

	describe("POST /links/scan", () => {
		it("should return scan results", () => {
			const scanDto = {
				assetCode: "USDC",
				amount: 100,
				memo: "test",
			};

			const result = controller.scan(scanDto);

			expect(result).toBeDefined();
			expect(result).toHaveProperty("isSafe");
			expect(result).toHaveProperty("riskScore");
			expect(result).toHaveProperty("alerts");
			expect(Array.isArray(result.alerts)).toBe(true);
		});

		it("should detect scams", () => {
			const scanDto = {
				assetCode: "USDC",
				amount: 100,
				memo: "Send to GABC123DEFG456HIJK789LMNO012PQRS345TUVW678XYZA901BCDE234",
			};

			const result = controller.scan(scanDto);

			expect(result.isSafe).toBe(false);
			expect(result.alerts.length).toBeGreaterThan(0);
		});
	});
});
