// @vitest-environment jsdom
//
// Automated accessibility checks for the QR/payment flow (#766). These
// components render the pay-to-receipt path exercised by
// e2e/tests/pay-to-receipt.spec.ts, so an axe violation here means a real
// user relying on a screen reader or keyboard could get stuck paying or
// receiving a payment.
import { describe, expect, it } from "vitest";
import { render } from "@testing-library/react";
import { axe, toHaveNoViolations } from "jest-axe";
import { QRPreview } from "@/components/QRPreview";
import { SigningSummary } from "@/components/SigningSummary";
import { ActivePaymentState } from "@/components/payment-states/ActivePaymentState";
import { PaidPaymentState } from "@/components/payment-states/PaidPaymentState";
import { ExpiredPaymentState } from "@/components/payment-states/ExpiredPaymentState";
import { RefundedPaymentState } from "@/components/payment-states/RefundedPaymentState";

expect.extend(toHaveNoViolations);

const activeStatus = {
  username: "alice",
  amount: "100",
  asset: "USDC",
  memo: null,
  destinationPublicKey: "GABC1234567890",
  expiresAt: null,
  swapOptions: null,
  acceptsMultipleAssets: false,
  acceptedAssets: null,
  userMessage: "Complete this payment to alice.",
  availableActions: ["pay"],
};

const paidStatus = {
  username: "alice",
  amount: "100",
  asset: "USDC",
  memo: null,
  transactionHash: "abc123",
  paidAt: new Date().toISOString(),
  userMessage: "Payment received.",
};

const expiredStatus = {
  username: "alice",
  amount: "100",
  asset: "USDC",
  memo: null,
  expiresAt: new Date().toISOString(),
  userMessage: "This link has expired.",
};

describe("QR/payment flow accessibility", () => {
  it("QRPreview with a value has no axe violations", async () => {
    const { container } = render(<QRPreview value="stellar:GABC?amount=100" />);
    expect(await axe(container)).toHaveNoViolations();
  });

  it("QRPreview placeholder (no value) has no axe violations", async () => {
    const { container } = render(<QRPreview />);
    expect(await axe(container)).toHaveNoViolations();
  });

  it("SigningSummary has no axe violations", async () => {
    const { container } = render(
      <SigningSummary
        action="purchase"
        amount={{ value: 100, asset: "USDC" }}
        details={[{ label: "Recipient", value: "alice" }]}
        expiry={new Date(Date.now() + 60_000)}
        fee={{ value: 1, asset: "USDC", percentage: 1 }}
      />,
    );
    expect(await axe(container)).toHaveNoViolations();
  });

  it("ActivePaymentState has no axe violations", async () => {
    const { container } = render(
      <ActivePaymentState
        status={activeStatus}
        onPaymentInitiated={() => {}}
        onPaymentCompleted={() => {}}
      />,
    );
    expect(await axe(container)).toHaveNoViolations();
  });

  it("PaidPaymentState has no axe violations", async () => {
    const { container } = render(<PaidPaymentState status={paidStatus} />);
    expect(await axe(container)).toHaveNoViolations();
  });

  it("ExpiredPaymentState has no axe violations", async () => {
    const { container } = render(<ExpiredPaymentState status={expiredStatus} />);
    expect(await axe(container)).toHaveNoViolations();
  });

  it("RefundedPaymentState has no axe violations", async () => {
    const { container } = render(<RefundedPaymentState status={paidStatus} />);
    expect(await axe(container)).toHaveNoViolations();
  });
});
