import React from "@react";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import '@testing-library/jest-dom';
import SettingsPage from "./page";

const mockProfile = {
  displayName: "Satoshi",
  colour: "#3b82f6",
  avatar: "https://example.com/avatar.png",
  bio: "Building decentralized tools.",
  twitter: "satoshi",
  discord: "satoshi#0001",
  github: "satoshi",
};

describe("SettingsPage", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("loads and displays profile data successfully", async () => {
    global.fetch = vi.fn().mockResolvedValueOnce({
      ok: true,
      json: async () => mockProfile,
    });

    render(<SettingsPage />);

    expect(screen.getByTestId("loading-state")).toBeInTheDocument();

    await waitFor(() => {
      expect(screen.getByDisplayValue("Satoshi")).toBeInTheDocument();
    });

    expect(screen.getByDisplayValue("Building decentralized tools.")).toBeInTheDocument();
  });

  it("handles load error gracefully", async () => {
    global.fetch = vi.fn().mockResolvedValueOnce({
      ok: false,
    });

    render(<SettingsPage />);

    await waitFor(() => {
      expect(screen.getByTestId("error-state")).toBeInTheDocument();
    });
  });

  it("shows validation errors for invalid inputs", async () => {
    global.fetch = vi.fn().mockResolvedValueOnce({
      ok: true,
      json: async () => mockProfile,
    });

    render(<SettingsPage />);

    await waitFor(() => {
      expect(screen.getByDisplayValue("Satoshi")).toBeInTheDocument();
    });

    const nameInput = screen.getByLabelText(/Display Name/i);
    fireEvent.change(nameInput, { target: { value: "" } });

    const colourInput = screen.getByLabelText(/Colour/i);
    fireEvent.change(colourInput, { target: { value: "invalid-hex" } });

    const saveButton = screen.getByRole("button", { name: /Save/i });
    fireEvent.click(saveButton);

    expect(screen.getByTestId("error-displayName")).toHaveTextContent("Display name is required");
    expect(screen.getByTestId("error-colour")).toHaveTextContent("Colour must be a valid hex code");
  });

  it("submits profile successfully on valid input", async () => {
    global.fetch = vi.fn()
      .mockResolvedValueOnce({
        ok: true,
        json: async () => mockProfile,
      })
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({ success: true }),
      });

    render(<SettingsPage />);

    await waitFor(() => {
      expect(screen.getByDisplayValue("Satoshi")).toBeInTheDocument();
    });

    const saveButton = screen.getByRole("button", { name: /Save/i });
    fireEvent.click(saveButton);

    await waitFor(() => {
      expect(screen.getByTestId("success-message")).toHaveTextContent("Profile updated successfully!");
    });
  });

  it("handles API save failure correctly", async () => {
    global.fetch = vi.fn()
      .mockResolvedValueOnce({
        ok: true,
        json: async () => mockProfile,
      })
      .mockResolvedValueOnce({
        ok: false,
        json: async () => ({ message: "Internal Server Error" }),
      });

    render(<SettingsPage />);

    await waitFor(() => {
      expect(screen.getByDisplayValue("Satoshi")).toBeInTheDocument();
    });

    const saveButton = screen.getByRole("button", { name: /Save/i });
    fireEvent.click(saveButton);

    await waitFor(() => {
      expect(screen.getByTestId("api-error")).toHaveTextContent("Internal Server Error");
    });
  });
});
