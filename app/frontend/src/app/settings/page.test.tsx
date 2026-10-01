import { render, screen, waitFor, fireEvent } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach, Mock } from "vitest";
import Settings from "./page";
import { fetchWithAuth } from "@/lib/api";

// Mock the API utilities
vi.mock("@/lib/api", () => ({
  getQuickexApiBase: () => "http://localhost:4000",
  fetchWithAuth: vi.fn(),
}));

// Mock react-i18next
vi.mock("react-i18next", () => ({
  useTranslation: () => ({
    t: (key: string) => key,
  }),
}));

describe("Settings Page", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("loads profile on mount and populates the form", async () => {
    const mockProfile = {
      username: "test_user",
      primaryColor: "#ff0000",
      avatarUrl: "https://example.com/avatar.png",
      bio: "Test bio",
      twitterHandle: "testhandle",
      discordHandle: "test#1234",
      githubHandle: "testgithub",
    };

    (fetchWithAuth as Mock).mockResolvedValueOnce({
      ok: true,
      json: async () => mockProfile,
    });

    render(<Settings />);

    // Wait for the profile to be loaded
    await waitFor(() => {
      expect(fetchWithAuth).toHaveBeenCalledWith("http://localhost:4000/profile");
    });

    // Check if form is populated
    await waitFor(() => {
      expect(screen.getByDisplayValue("test_user")).toBeInTheDocument();
      expect(screen.getByDisplayValue("https://example.com/avatar.png")).toBeInTheDocument();
      expect(screen.getByDisplayValue("Test bio")).toBeInTheDocument();
      expect(screen.getByDisplayValue("testhandle")).toBeInTheDocument();
      expect(screen.getByDisplayValue("test#1234")).toBeInTheDocument();
      expect(screen.getByDisplayValue("testgithub")).toBeInTheDocument();
    });
  });

  it("calls save API endpoint when Save button is clicked", async () => {
    (fetchWithAuth as Mock).mockResolvedValue({
      ok: true,
      json: async () => ({}),
    });

    render(<Settings />);

    const saveButtons = screen.getAllByText("saveChanges");
    fireEvent.click(saveButtons[0]);

    await waitFor(() => {
      expect(fetchWithAuth).toHaveBeenCalledWith("http://localhost:4000/profile", expect.objectContaining({
        method: "PUT",
        headers: { "Content-Type": "application/json" },
      }));
    });
  });
});
