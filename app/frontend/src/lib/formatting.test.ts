import { describe, expect, it } from "vitest";
import { formatAssetAmount, formatDateTime, formatNumber } from "./formatting";

describe("formatting (FE-63)", () => {
  it.each([
    ["en-US", "1234567.890123", "1,234,567.890123"],
    ["es-ES", "1234567.890123", "1.234.567,890123"],
    ["fr-FR", "1234567.890123", "1\u202f234\u202f567,890123"],
  ])("formats a number with the %s locale", (locale, value, expected) => {
    expect(formatNumber(value, locale)).toBe(expected);
  });

  it("preserves precise asset decimals without floating-point rounding", () => {
    expect(formatAssetAmount("12345.6789012", "USDC", "es-ES")).toBe(
      "12.345,6789012 USDC",
    );
    expect(formatAssetAmount("0.0000001", "XLM", "fr-FR")).toBe(
      "0,0000001 XLM",
    );
  });

  it("formats dates using the active locale", () => {
    const value = new Date("2026-01-22T11:30:00Z");
    expect(formatDateTime(value, "fr-FR")).toBe(
      new Intl.DateTimeFormat("fr-FR", {
        dateStyle: "medium",
        timeStyle: "short",
      }).format(value),
    );
  });
});
