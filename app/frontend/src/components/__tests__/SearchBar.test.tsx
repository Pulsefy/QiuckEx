// @vitest-environment jsdom
import { render, screen, waitFor, fireEvent } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import { axe, toHaveNoViolations } from "jest-axe";
import { SearchBar } from "../SearchBar";
import { useProfileSearch } from "@/hooks/useDiscoveryProfiles";

vi.mock("@/hooks/useDiscoveryProfiles", () => ({
  useProfileSearch: vi.fn(),
}));

expect.extend(toHaveNoViolations);

const mockedUseProfileSearch = vi.mocked(useProfileSearch);

describe("SearchBar", () => {
  beforeEach(() => {
    mockedUseProfileSearch.mockReset();
  });

  it("has combobox semantics when closed", () => {
    mockedUseProfileSearch.mockReturnValue({
      isLoading: false,
      results: [],
      error: null,
    });

    render(<SearchBar />);
    const input = screen.getByRole("combobox");
    expect(input).toHaveAttribute("aria-expanded", "false");
    expect(input).toHaveAttribute("aria-controls");
  });

  it("announces results and uses listbox/option with keyboard navigation", async () => {
    mockedUseProfileSearch.mockReturnValue({
      isLoading: false,
      results: [
        { id: "1", username: "alice", publicKey: "GABC", lastActiveAt: "", createdAt: "" },
        { id: "2", username: "bob", publicKey: "GDEF", lastActiveAt: "", createdAt: "" },
      ],
      error: null,
    });

    render(<SearchBar />);
    const input = screen.getByRole("combobox");

    fireEvent.change(input, { target: { value: "al" } });
    expect(input).toHaveAttribute("aria-expanded", "true");

    await waitFor(() => {
      expect(screen.getByRole("listbox")).toBeInTheDocument();
    });

    const options = screen.getAllByRole("option");
    expect(options).toHaveLength(2);

    fireEvent.keyDown(input, { key: "ArrowDown" });
    expect(input).toHaveAttribute("aria-activedescendant", options[0].id);
    expect(options[0]).toHaveAttribute("aria-selected", "true");

    fireEvent.keyDown(input, { key: "ArrowDown" });
    expect(options[1]).toHaveAttribute("aria-selected", "true");

    fireEvent.keyDown(input, { key: "ArrowUp" });
    expect(options[0]).toHaveAttribute("aria-selected", "true");
  });

  it("closes on Escape", async () => {
    mockedUseProfileSearch.mockReturnValue({
      isLoading: false,
      results: [
        { id: "1", username: "alice", publicKey: "GABC", lastActiveAt: "", createdAt: "" },
      ],
      error: null,
    });

    render(<SearchBar />);
    const input = screen.getByRole("combobox");
    fireEvent.change(input, { target: { value: "al" } });

    await waitFor(() => expect(screen.getByRole("listbox")).toBeInTheDocument());
    fireEvent.keyDown(input, { key: "Escape" });
    await waitFor(() => expect(screen.queryByRole("listbox")).not.toBeInTheDocument());
    expect(input).toHaveAttribute("aria-expanded", "false");
  });

  it("has no axe violations when open with results", async () => {
    mockedUseProfileSearch.mockReturnValue({
      isLoading: false,
      results: [
        { id: "1", username: "alice", publicKey: "GABC", lastActiveAt: "", createdAt: "" },
      ],
      error: null,
    });

    const { container } = render(<SearchBar />);
    const input = screen.getByRole("combobox");
    fireEvent.change(input, { target: { value: "al" } });
    await waitFor(() => expect(screen.getByRole("listbox")).toBeInTheDocument());

    expect(await axe(container)).toHaveNoViolations();
  });
});
