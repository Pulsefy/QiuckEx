import { render, screen } from "@testing-library/react";
import { SigningSummary } from "../SigningSummary";

describe("SigningSummary", () => {
  const defaultProps = {
    action: "bid" as const,
    amount: { value: 100, asset: "USDC" },
    details: [
      { label: "Target", value: "@tester" },
    ],
  };

  it("renders the action label correctly", () => {
    render(<SigningSummary {...defaultProps} />);
    expect(screen.getByText("Place Auction Bid")).toBeInTheDocument();
  });

  it("renders the amount and asset", () => {
    render(<SigningSummary {...defaultProps} />);
    expect(screen.getByText("100")).toBeInTheDocument();
    expect(screen.getByText("USDC")).toBeInTheDocument();
  });

  it("shows network mismatch warning when networks don't match", () => {
    render(
      <SigningSummary 
        {...defaultProps} 
        network="Stellar Mainnet" 
        targetNetwork="Stellar Testnet" 
      />
    );
    expect(screen.getByText(/Your wallet is on Stellar Mainnet/)).toBeInTheDocument();
  });

  it("shows expiry warning when payload is expired", () => {
    const pastDate = new Date(Date.now() - 10000);
    render(<SigningSummary {...defaultProps} expiry={pastDate} />);
    expect(screen.getByText(/This transaction payload has expired/)).toBeInTheDocument();
    expect(screen.getByText("Expired")).toBeInTheDocument();
  });
});
