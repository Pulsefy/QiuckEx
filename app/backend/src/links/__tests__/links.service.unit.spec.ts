import { Test, TestingModule } from "@nestjs/testing";
import { LinksService } from "../links.service";
import { PathPreviewService } from "../../stellar/path-preview.service";
import { PrivacyService } from "../../privacy/privacy.service";
import { LinkValidationError, LinkErrorCode } from "../errors";

describe("LinksService", () => {
  let service: LinksService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        LinksService,
        {
          provide: PathPreviewService,
          useValue: {
            previewPaths: jest.fn().mockResolvedValue({ paths: [] }),
          },
        },
        {
          provide: PrivacyService,
          useValue: {
            encryptRecipientForViewKey: jest
              .fn()
              .mockReturnValue("encrypted-data"),
          },
        },
      ],
    }).compile();

    service = module.get<LinksService>(LinksService);
  });

  it("should be defined", () => {
    expect(service).toBeDefined();
  });

  // ---------------------------------------------------------------------------
  // generateMetadata – happy path
  // ---------------------------------------------------------------------------
  describe("generateMetadata", () => {
    it("should generate metadata for a valid XLM payment", async () => {
      const result = await service.generateMetadata({
        amount: 100,
        asset: "XLM",
        memo: "Test payment",
      });

      expect(result.amount).toBe("100.0000000");
      expect(result.asset).toBe("XLM");
      expect(result.memo).toBe("Test payment");
      expect(result.memoType).toBe("text");
      expect(result.privacy).toBe(false);
      expect(result.canonical).toContain("amount=100.0000000");
      expect(result.canonical).toContain("asset=XLM");
    });

    it("should normalize amount to 7 decimal places", async () => {
      const result = await service.generateMetadata({
        amount: 1.5,
        asset: "XLM",
      });

      expect(result.amount).toBe("1.5000000");
      expect(result.metadata.normalized).toBe(true);
    });

    it("should default asset to XLM when not provided", async () => {
      const result = await service.generateMetadata({ amount: 50 });

      expect(result.asset).toBe("XLM");
    });

    it("should set expiresAt when expirationDays is provided", async () => {
      const before = new Date();
      const result = await service.generateMetadata({
        amount: 10,
        expirationDays: 7,
      });

      expect(result.expiresAt).toBeInstanceOf(Date);
      // expiresAt should be ~7 days from now
      const diffDays = Math.round(
        ((result.expiresAt as Date).getTime() - before.getTime()) /
          (1000 * 60 * 60 * 24),
      );
      expect(diffDays).toBeGreaterThanOrEqual(6);
      expect(diffDays).toBeLessThanOrEqual(8);
    });

    it("should set privacy flag correctly", async () => {
      const result = await service.generateMetadata({
        amount: 10,
        privacy: true,
      });

      expect(result.privacy).toBe(true);
    });
  });

  // ---------------------------------------------------------------------------
  // Amount validation
  // ---------------------------------------------------------------------------
  describe("amount validation", () => {
    it("should reject NaN amounts", async () => {
      await expect(service.generateMetadata({ amount: NaN })).rejects.toThrow(
        LinkValidationError,
      );

      await expect(service.generateMetadata({ amount: NaN })).rejects.toThrow(
        /Amount must be a valid number/,
      );
    });

    it("should reject amounts below minimum", async () => {
      try {
        await service.generateMetadata({ amount: 0 });
        fail("Expected LinkValidationError");
      } catch (err) {
        expect(err).toBeInstanceOf(LinkValidationError);
        expect((err as LinkValidationError).code).toBe(
          LinkErrorCode.AMOUNT_TOO_LOW,
        );
      }
    });

    it("should reject amounts above maximum", async () => {
      try {
        await service.generateMetadata({ amount: 2000000 });
        fail("Expected LinkValidationError");
      } catch (err) {
        expect(err).toBeInstanceOf(LinkValidationError);
        expect((err as LinkValidationError).code).toBe(
          LinkErrorCode.AMOUNT_TOO_HIGH,
        );
      }
    });

    it("should accept the minimum valid amount", async () => {
      const result = await service.generateMetadata({
        amount: 0.0000001,
        asset: "XLM",
      });
      expect(result.amount).toBe("0.0000001");
    });

    it("should accept the maximum valid amount", async () => {
      const result = await service.generateMetadata({
        amount: 1000000,
        asset: "XLM",
      });
      expect(result.amount).toBe("1000000.0000000");
    });
  });

  // ---------------------------------------------------------------------------
  // Memo validation
  // ---------------------------------------------------------------------------
  describe("memo validation", () => {
    it("should return null memo when empty string provided", async () => {
      const result = await service.generateMetadata({
        amount: 10,
        memo: "",
      });
      expect(result.memo).toBeNull();
    });

    it("should return null memo when whitespace-only provided", async () => {
      const result = await service.generateMetadata({
        amount: 10,
        memo: "   ",
      });
      expect(result.memo).toBeNull();
    });

    it("should trim and sanitize memo", async () => {
      const result = await service.generateMetadata({
        amount: 10,
        memo: "  hello <world>  ",
      });
      expect(result.memo).toBe("hello world");
    });

    it("should reject memos exceeding max length", async () => {
      const longMemo = "a".repeat(29); // MAX_LENGTH is 28
      try {
        await service.generateMetadata({ amount: 10, memo: longMemo });
        fail("Expected LinkValidationError");
      } catch (err) {
        expect(err).toBeInstanceOf(LinkValidationError);
        expect((err as LinkValidationError).code).toBe(
          LinkErrorCode.MEMO_TOO_LONG,
        );
      }
    });

    it("should reject invalid memo types", async () => {
      try {
        await service.generateMetadata({
          amount: 10,
          memo: "test",
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          memoType: "invalid_type" as any,
        });
        fail("Expected LinkValidationError");
      } catch (err) {
        expect(err).toBeInstanceOf(LinkValidationError);
        expect((err as LinkValidationError).code).toBe(
          LinkErrorCode.INVALID_MEMO_TYPE,
        );
      }
    });

    it("should accept valid memo types", async () => {
      for (const memoType of ["text", "id", "hash", "return"] as const) {
        const result = await service.generateMetadata({
          amount: 10,
          memo: "test",
          memoType,
        });
        expect(result.memoType).toBe(memoType);
      }
    });
  });

  // ---------------------------------------------------------------------------
  // Asset validation
  // ---------------------------------------------------------------------------
  describe("asset validation", () => {
    it("should accept whitelisted assets", async () => {
      for (const asset of ["XLM", "USDC", "AQUA", "yXLM"]) {
        const result = await service.generateMetadata({ amount: 10, asset });
        expect(result.asset).toBe(asset);
      }
    });

    it("should reject non-whitelisted assets", async () => {
      try {
        await service.generateMetadata({ amount: 10, asset: "DOGE" });
        fail("Expected LinkValidationError");
      } catch (err) {
        expect(err).toBeInstanceOf(LinkValidationError);
        expect((err as LinkValidationError).code).toBe(
          LinkErrorCode.ASSET_NOT_WHITELISTED,
        );
      }
    });

    it("should set asset metadata correctly for native XLM", async () => {
      const result = await service.generateMetadata({
        amount: 10,
        asset: "XLM",
      });
      expect(result.metadata.assetType).toBe("native");
      expect(result.metadata.assetIssuer).toBeNull();
    });

    it("should set asset metadata for non-native assets", async () => {
      const result = await service.generateMetadata({
        amount: 10,
        asset: "USDC",
      });
      expect(result.metadata.assetType).toBe("credit_alphanum4");
      expect(result.metadata.assetIssuer).toBeDefined();
    });
  });

  // ---------------------------------------------------------------------------
  // Username validation
  // ---------------------------------------------------------------------------
  describe("username validation", () => {
    it("should accept valid usernames", async () => {
      const result = await service.generateMetadata({
        amount: 10,
        username: "john_doe",
      });
      expect(result.username).toBe("john_doe");
    });

    it("should lowercase usernames", async () => {
      const result = await service.generateMetadata({
        amount: 10,
        username: "JohnDoe",
      });
      expect(result.username).toBe("johndoe");
    });

    it("should reject usernames shorter than 3 characters", async () => {
      try {
        await service.generateMetadata({ amount: 10, username: "ab" });
        fail("Expected LinkValidationError");
      } catch (err) {
        expect(err).toBeInstanceOf(LinkValidationError);
        expect((err as LinkValidationError).code).toBe(
          LinkErrorCode.INVALID_USERNAME,
        );
      }
    });

    it("should reject reserved usernames", async () => {
      try {
        await service.generateMetadata({ amount: 10, username: "admin" });
        fail("Expected LinkValidationError");
      } catch (err) {
        expect(err).toBeInstanceOf(LinkValidationError);
        expect((err as LinkValidationError).code).toBe(
          LinkErrorCode.USERNAME_RESERVED,
        );
      }
    });

    it("should return null when username is empty", async () => {
      const result = await service.generateMetadata({
        amount: 10,
        username: "",
      });
      expect(result.username).toBeNull();
    });
  });

  // ---------------------------------------------------------------------------
  // Destination validation
  // ---------------------------------------------------------------------------
  describe("destination validation", () => {
    it("should accept valid Stellar public keys", async () => {
      // Stellar keys use base32 charset: A-Z + 2-7 (56 chars total, starts with G)
      const validKey = "G" + "A".repeat(55);
      expect(validKey).toHaveLength(56);
      const result = await service.generateMetadata({
        amount: 10,
        destination: validKey,
      });
      expect(result.destination).toBe(validKey);
    });

    it("should reject invalid destination keys", async () => {
      try {
        await service.generateMetadata({
          amount: 10,
          destination: "INVALID_KEY",
        });
        fail("Expected LinkValidationError");
      } catch (err) {
        expect(err).toBeInstanceOf(LinkValidationError);
        expect((err as LinkValidationError).code).toBe(
          LinkErrorCode.INVALID_DESTINATION,
        );
      }
    });

    it("should return null when destination is empty", async () => {
      const result = await service.generateMetadata({
        amount: 10,
        destination: "",
      });
      expect(result.destination).toBeNull();
    });
  });

  // ---------------------------------------------------------------------------
  // acceptedAssets
  // ---------------------------------------------------------------------------
  describe("acceptedAssets", () => {
    it("should return null when acceptedAssets is not provided", async () => {
      const result = await service.generateMetadata({ amount: 10 });
      expect(result.acceptedAssets).toBeNull();
    });

    it("should always include the destination asset in acceptedAssets", async () => {
      const result = await service.generateMetadata({
        amount: 10,
        asset: "XLM",
        acceptedAssets: ["USDC"],
      });
      expect(result.acceptedAssets).toContain("XLM");
      expect(result.acceptedAssets).toContain("USDC");
    });

    it("should reject non-whitelisted acceptedAssets", async () => {
      try {
        await service.generateMetadata({
          amount: 10,
          acceptedAssets: ["DOGE"],
        });
        fail("Expected LinkValidationError");
      } catch (err) {
        expect(err).toBeInstanceOf(LinkValidationError);
        expect((err as LinkValidationError).code).toBe(
          LinkErrorCode.ASSET_NOT_WHITELISTED,
        );
      }
    });

    it("should deduplicate acceptedAssets", async () => {
      const result = await service.generateMetadata({
        amount: 10,
        asset: "XLM",
        acceptedAssets: ["XLM", "USDC", "XLM"],
      });
      const xlmCount = result.acceptedAssets!.filter((a) => a === "XLM").length;
      expect(xlmCount).toBe(1);
    });
  });

  // ---------------------------------------------------------------------------
  // Security level
  // ---------------------------------------------------------------------------
  describe("security level", () => {
    it("should return 'low' for minimal request", async () => {
      const result = await service.generateMetadata({ amount: 10 });
      expect(result.metadata.securityLevel).toBe("low");
    });

    it("should return 'medium' when memo is provided", async () => {
      const result = await service.generateMetadata({
        amount: 10,
        memo: "test",
      });
      expect(result.metadata.securityLevel).toBe("medium");
    });

    it("should return 'high' when multiple security fields are set", async () => {
      const result = await service.generateMetadata({
        amount: 10,
        memo: "test",
        expirationDays: 7,
        privacy: true,
      });
      expect(result.metadata.securityLevel).toBe("high");
    });
  });

  // ---------------------------------------------------------------------------
  // Reference ID validation
  // ---------------------------------------------------------------------------
  describe("referenceId validation", () => {
    it("should accept valid reference IDs", async () => {
      const result = await service.generateMetadata({
        amount: 10,
        referenceId: "inv-123_abc",
      });
      expect(result.referenceId).toBe("inv-123_abc");
    });

    it("should reject reference IDs exceeding max length", async () => {
      try {
        await service.generateMetadata({
          amount: 10,
          referenceId: "a".repeat(65),
        });
        fail("Expected LinkValidationError");
      } catch (err) {
        expect(err).toBeInstanceOf(LinkValidationError);
        expect((err as LinkValidationError).code).toBe(
          LinkErrorCode.INVALID_REFERENCE_ID,
        );
      }
    });

    it("should reject reference IDs with invalid characters", async () => {
      try {
        await service.generateMetadata({
          amount: 10,
          referenceId: "inv 123!",
        });
        fail("Expected LinkValidationError");
      } catch (err) {
        expect(err).toBeInstanceOf(LinkValidationError);
        expect((err as LinkValidationError).code).toBe(
          LinkErrorCode.INVALID_REFERENCE_ID,
        );
      }
    });
  });

  // ---------------------------------------------------------------------------
  // Expiration validation
  // ---------------------------------------------------------------------------
  describe("expiration validation", () => {
    it("should reject negative expiration days", async () => {
      await expect(
        service.generateMetadata({ amount: 10, expirationDays: -1 }),
      ).rejects.toThrow(LinkValidationError);
    });

    it("should reject expiration days above 365", async () => {
      await expect(
        service.generateMetadata({ amount: 10, expirationDays: 400 }),
      ).rejects.toThrow(LinkValidationError);
    });

    it("should return null expiresAt when no expirationDays", async () => {
      const result = await service.generateMetadata({ amount: 10 });
      expect(result.expiresAt).toBeNull();
    });
  });
});
