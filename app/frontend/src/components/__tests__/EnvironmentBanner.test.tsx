import { render, screen } from "@testing-library/react";
import { describe, it, expect, vi } from "vitest";
import { EnvironmentBanner } from "../EnvironmentBanner";
import * as BootstrapContext from "../../contexts/BootstrapContext";

vi.mock("../../contexts/BootstrapContext", () => ({
  useBootstrap: vi.fn(),
}));

describe("EnvironmentBanner", () => {
  it("renders null while loading", () => {
    vi.mocked(BootstrapContext.useBootstrap).mockReturnValue({
      isLoading: true,
      config: {} as any,
      error: null,
    });

    const { container } = render(<EnvironmentBanner />);
    expect(container.firstChild).toBeNull();
  });

  it("renders null in production environment (mainnet network)", () => {
    vi.mocked(BootstrapContext.useBootstrap).mockReturnValue({
      isLoading: false,
      config: {
        backendMetadata: {
          environmentName: undefined,
        },
        network: {
          environment: "mainnet",
        },
      } as any,
      error: null,
    });

    const { container } = render(<EnvironmentBanner />);
    expect(container.firstChild).toBeNull();
  });

  it("renders null in production environment (explicit environmentName)", () => {
    vi.mocked(BootstrapContext.useBootstrap).mockReturnValue({
      isLoading: false,
      config: {
        backendMetadata: {
          environmentName: "production",
        },
        network: {
          environment: "testnet",
        },
      } as any,
      error: null,
    });

    const { container } = render(<EnvironmentBanner />);
    expect(container.firstChild).toBeNull();
  });

  it("renders banner in testnet", () => {
    vi.mocked(BootstrapContext.useBootstrap).mockReturnValue({
      isLoading: false,
      config: {
        backendMetadata: {
          environmentName: undefined,
        },
        network: {
          environment: "testnet",
        },
      } as any,
      error: null,
    });

    render(<EnvironmentBanner />);
    expect(screen.getByTestId("environment-banner")).toBeInTheDocument();
    expect(screen.getByText(/This is the TESTNET environment/i)).toBeInTheDocument();
    expect(screen.queryByText(/Branch:/)).toBeNull();
  });

  it("renders banner with branch metadata in preview environment", () => {
    vi.mocked(BootstrapContext.useBootstrap).mockReturnValue({
      isLoading: false,
      config: {
        backendMetadata: {
          environmentName: "preview",
          branchName: "feature/awesome-new-stuff",
        },
        network: {
          environment: "testnet",
        },
      } as any,
      error: null,
    });

    render(<EnvironmentBanner />);
    expect(screen.getByTestId("environment-banner")).toBeInTheDocument();
    expect(screen.getByText(/This is the PREVIEW environment/i)).toBeInTheDocument();
    expect(screen.getByText("Branch: feature/awesome-new-stuff")).toBeInTheDocument();
  });
});
