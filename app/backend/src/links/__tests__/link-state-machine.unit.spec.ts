import {
  LinkState,
  canTransition,
  applyTransition,
  getAvailableTransitions,
} from "../link-state-machine";

describe("LinkStateMachine", () => {
  // ---------------------------------------------------------------------------
  // canTransition
  // ---------------------------------------------------------------------------
  describe("canTransition", () => {
    it("should allow DRAFT → ACTIVE", () => {
      expect(canTransition(LinkState.DRAFT, LinkState.ACTIVE)).toBe(true);
    });

    it("should allow ACTIVE → EXPIRED", () => {
      expect(canTransition(LinkState.ACTIVE, LinkState.EXPIRED)).toBe(true);
    });

    it("should allow ACTIVE → PAID", () => {
      expect(canTransition(LinkState.ACTIVE, LinkState.PAID)).toBe(true);
    });

    it("should allow EXPIRED → ACTIVE (re-activation)", () => {
      expect(canTransition(LinkState.EXPIRED, LinkState.ACTIVE)).toBe(true);
    });

    it("should allow PAID → REFUNDED", () => {
      expect(canTransition(LinkState.PAID, LinkState.REFUNDED)).toBe(true);
    });

    it("should NOT allow DRAFT → PAID", () => {
      expect(canTransition(LinkState.DRAFT, LinkState.PAID)).toBe(false);
    });

    it("should NOT allow DRAFT → EXPIRED", () => {
      expect(canTransition(LinkState.DRAFT, LinkState.EXPIRED)).toBe(false);
    });

    it("should NOT allow ACTIVE → DRAFT", () => {
      expect(canTransition(LinkState.ACTIVE, LinkState.DRAFT)).toBe(false);
    });

    it("should NOT allow EXPIRED → PAID directly", () => {
      expect(canTransition(LinkState.EXPIRED, LinkState.PAID)).toBe(false);
    });

    it("should NOT allow REFUNDED → any state", () => {
      expect(canTransition(LinkState.REFUNDED, LinkState.ACTIVE)).toBe(false);
      expect(canTransition(LinkState.REFUNDED, LinkState.PAID)).toBe(false);
      expect(canTransition(LinkState.REFUNDED, LinkState.DRAFT)).toBe(false);
    });

    it("should NOT allow PAID → ACTIVE", () => {
      expect(canTransition(LinkState.PAID, LinkState.ACTIVE)).toBe(false);
    });

    it("should NOT allow same-state transition (ACTIVE → ACTIVE)", () => {
      expect(canTransition(LinkState.ACTIVE, LinkState.ACTIVE)).toBe(false);
    });
  });

  // ---------------------------------------------------------------------------
  // applyTransition
  // ---------------------------------------------------------------------------
  describe("applyTransition", () => {
    it("should return the target state for valid transitions", () => {
      expect(applyTransition(LinkState.DRAFT, LinkState.ACTIVE)).toBe(
        LinkState.ACTIVE,
      );
      expect(applyTransition(LinkState.ACTIVE, LinkState.PAID)).toBe(
        LinkState.PAID,
      );
      expect(applyTransition(LinkState.ACTIVE, LinkState.EXPIRED)).toBe(
        LinkState.EXPIRED,
      );
      expect(applyTransition(LinkState.PAID, LinkState.REFUNDED)).toBe(
        LinkState.REFUNDED,
      );
    });

    it("should throw for invalid transitions", () => {
      expect(() => applyTransition(LinkState.DRAFT, LinkState.PAID)).toThrow(
        "Invalid link state transition",
      );
    });

    it("should throw for REFUNDED → any", () => {
      expect(() =>
        applyTransition(LinkState.REFUNDED, LinkState.ACTIVE),
      ).toThrow("Invalid link state transition: REFUNDED -> ACTIVE");
    });
  });

  // ---------------------------------------------------------------------------
  // getAvailableTransitions
  // ---------------------------------------------------------------------------
  describe("getAvailableTransitions", () => {
    it("should return [ACTIVE] for DRAFT", () => {
      expect(getAvailableTransitions(LinkState.DRAFT)).toEqual([
        LinkState.ACTIVE,
      ]);
    });

    it("should return [EXPIRED, PAID] for ACTIVE", () => {
      const transitions = getAvailableTransitions(LinkState.ACTIVE);
      expect(transitions).toContain(LinkState.EXPIRED);
      expect(transitions).toContain(LinkState.PAID);
      expect(transitions).toHaveLength(2);
    });

    it("should return [ACTIVE] for EXPIRED", () => {
      expect(getAvailableTransitions(LinkState.EXPIRED)).toEqual([
        LinkState.ACTIVE,
      ]);
    });

    it("should return [REFUNDED] for PAID", () => {
      expect(getAvailableTransitions(LinkState.PAID)).toEqual([
        LinkState.REFUNDED,
      ]);
    });

    it("should return [] for REFUNDED (terminal state)", () => {
      expect(getAvailableTransitions(LinkState.REFUNDED)).toEqual([]);
    });

    it("should return a new array (not a reference to internal state)", () => {
      const a = getAvailableTransitions(LinkState.ACTIVE);
      const b = getAvailableTransitions(LinkState.ACTIVE);
      expect(a).not.toBe(b);
      expect(a).toEqual(b);
    });
  });
});
