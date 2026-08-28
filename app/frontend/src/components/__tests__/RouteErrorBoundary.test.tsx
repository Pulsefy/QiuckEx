/**
 * @vitest-environment jsdom
 */
import "@testing-library/jest-dom/vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { RouteErrorBoundary } from "../RouteErrorBoundary";
import * as errorReporterModule from "@/lib/errorReporter";

// Mock errorReporter.captureError
vi.mock("@/lib/errorReporter", () => ({
  errorReporter: {
    captureError: vi.fn(),
  },
}));

// Suppress console.error from React boundary log
beforeEach(() => {
  vi.spyOn(console, "error").mockImplementation(() => {});
  vi.mocked(errorReporterModule.errorReporter.captureError).mockClear();
});

function ThrowingChild() {
  throw new Error("Test render error");
}

function WorkingChild() {
  return <div>Child content</div>;
}

describe("RouteErrorBoundary", () => {
  it("renders children when no error occurs", () => {
    render(
      <RouteErrorBoundary routeLabel="Test">
        <WorkingChild />
      </RouteErrorBoundary>,
    );

    expect(screen.getByText("Child content")).toBeInTheDocument();
  });

  it("renders fallback UI when a child throws", () => {
    render(
      <RouteErrorBoundary routeLabel="Dashboard">
        <ThrowingChild />
      </RouteErrorBoundary>,
    );

    expect(screen.getByText("Something went wrong")).toBeInTheDocument();
    expect(screen.getByText("Dashboard")).toBeInTheDocument();
    // The raw stack trace should NOT be visible
    expect(screen.queryByText("Test render error")).not.toBeInTheDocument();
  });

  it("reports error to errorReporter with route context", () => {
    const captureErrorSpy = vi.mocked(errorReporterModule.errorReporter.captureError);

    render(
      <RouteErrorBoundary routeLabel="Dashboard">
        <ThrowingChild />
      </RouteErrorBoundary>,
    );

    expect(captureErrorSpy).toHaveBeenCalled();
    const [error, context] = captureErrorSpy.mock.calls[0];
    expect(error).toBeInstanceOf(Error);
    expect(error.message).toBe("Test render error");
    expect(context).toMatchObject({
      extra: {
        routeLabel: "Dashboard",
        source: "route-error-boundary",
      },
    });
  });

  it("shows retry and homepage buttons", () => {
    render(
      <RouteErrorBoundary routeLabel="Pay">
        <ThrowingChild />
      </RouteErrorBoundary>,
    );

    expect(screen.getByText("Try again")).toBeInTheDocument();
    expect(screen.getByText("Go to homepage")).toBeInTheDocument();
  });

  it("renders support reference when supportReference is provided", () => {
    render(
      <RouteErrorBoundary routeLabel="Payment" supportReference="https://quickex.to/support">
        <ThrowingChild />
      </RouteErrorBoundary>,
    );

    expect(screen.getByText("support")).toBeInTheDocument();
  });

  it("does not render support reference when supportReference is not provided", () => {
    render(
      <RouteErrorBoundary routeLabel="Dashboard">
        <ThrowingChild />
      </RouteErrorBoundary>,
    );

    expect(screen.queryByText("support")).not.toBeInTheDocument();
  });

  it("never shows raw stack trace in fallback UI", () => {
    render(
      <RouteErrorBoundary routeLabel="Test">
        <ThrowingChild />
      </RouteErrorBoundary>,
    );

    const fallbackText = screen.getByRole("heading", { name: "Something went wrong" }).closest("section")?.textContent ?? "";
    // Should not contain file paths or stack trace fragments
    expect(fallbackText).not.toMatch(/at\s|\.tsx|\.ts:|\.jsx|\.js:/);
  });

  it("resets error state when clicking Try again (triggers reload)", () => {
    const reloadSpy = vi.fn();
    Object.defineProperty(window, "location", {
      value: { reload: reloadSpy },
      writable: true,
    });

    render(
      <RouteErrorBoundary routeLabel="Test">
        <ThrowingChild />
      </RouteErrorBoundary>,
    );

    fireEvent.click(screen.getByText("Try again"));
    expect(reloadSpy).toHaveBeenCalled();
  });

  it("navigates to homepage on click (via link href)", () => {
    render(
      <RouteErrorBoundary routeLabel="Test">
        <ThrowingChild />
      </RouteErrorBoundary>,
    );

    const homeLink = screen.getByText("Go to homepage");
    expect(homeLink).toHaveAttribute("href", "/");
  });
});
