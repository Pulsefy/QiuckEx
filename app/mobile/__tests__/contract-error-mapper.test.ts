import {
  mapContractError,
  extractContractErrorCode,
  QuickexErrorCode,
} from "../utils/contract-error-mapper";

describe("Contract Error Mapper", () => {
  describe("extractContractErrorCode", () => {
    it("should return numeric codes directly when passed numbers", () => {
      expect(extractContractErrorCode(100)).toBe(100);
      expect(extractContractErrorCode(307)).toBe(307);
      expect(extractContractErrorCode(308)).toBe(308);
      expect(extractContractErrorCode(500)).toBe(500);
    });

    it("should extract code from numeric patterns in strings", () => {
      expect(extractContractErrorCode("Host-side error code: 307")).toBe(307);
      expect(extractContractErrorCode("Soroban error 308 occurred")).toBe(308);
      expect(extractContractErrorCode("Error: 500")).toBe(500);
    });

    it("should extract code from enum name patterns in strings", () => {
      expect(extractContractErrorCode("QuickexError::EscrowNotExpired")).toBe(QuickexErrorCode.EscrowNotExpired);
      expect(extractContractErrorCode("Contract error: NonceAlreadyUsed")).toBe(QuickexErrorCode.NonceAlreadyUsed);
      expect(extractContractErrorCode("SignatureExpired")).toBe(QuickexErrorCode.SignatureExpired);
    });

    it("should extract code from object fields", () => {
      expect(extractContractErrorCode({ code: 307 })).toBe(307);
      expect(extractContractErrorCode({ status: 308 })).toBe(308);
      expect(extractContractErrorCode({ message: "EscrowExpired" })).toBe(QuickexErrorCode.EscrowExpired);
      expect(extractContractErrorCode({ error: { code: 500 } })).toBe(500);
    });

    it("should return null or the input string if no code/enum is matching", () => {
      expect(extractContractErrorCode(null)).toBeNull();
      expect(extractContractErrorCode(undefined)).toBeNull();
      expect(extractContractErrorCode("Some generic api error")).toBe("Some generic api error");
    });
  });

  describe("mapContractError", () => {
    it("should map known integer codes to user friendly title and recovery actions", () => {
      const escrowNotExpired = mapContractError(308);
      expect(escrowNotExpired.title).toBe("Refund Locked");
      expect(escrowNotExpired.actionType).toBe("retry");
      expect(escrowNotExpired.recoveryGuidance).toContain("lockup period");

      const escrowExpired = mapContractError(307);
      expect(escrowExpired.title).toBe("Escrow Lockup Expired");
      expect(escrowExpired.actionType).toBe("go_back");

      const spent = mapContractError(304);
      expect(spent.title).toBe("Funds Already Claimed");
      expect(spent.actionType).toBe("refresh_balance");

      const signatureExpired = mapContractError(501);
      expect(signatureExpired.title).toBe("Signature Timed Out");
      expect(signatureExpired.actionType).toBe("retry");
    });

    it("should map string errors containing matches to correct mappings", () => {
      const errorStr = mapContractError("QuickexError::EscrowNotExpired");
      expect(errorStr.title).toBe("Refund Locked");
      expect(errorStr.code).toBe(308);
    });

    it("should fallback gracefully for unknown/generic errors", () => {
      const fallback = mapContractError("Random network failure");
      expect(fallback.title).toBe("Contract Execution Failed");
      expect(fallback.code).toBe("Random network failure");
      expect(fallback.actionType).toBe("retry");
      expect(fallback.recoveryGuidance).toContain("Stellar wallet");
    });
  });
});
