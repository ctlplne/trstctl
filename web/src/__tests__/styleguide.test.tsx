import { act, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { Styleguide } from "@/pages/Styleguide";

describe("served styleguide", () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it("renders every section and follows the full ARIA tab keyboard contract", () => {
    vi.useFakeTimers();
    render(<Styleguide />);

    expect(screen.getByRole("heading", { name: "Design system" })).toBeInTheDocument();
    expect(screen.getByRole("tablist", { name: "Design system sections" })).toBeInTheDocument();
    expect(screen.getByText("Internal component, state, content, and accessibility contract.")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Color tokens" })).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Browse patterns" }));
    expect(screen.getByRole("tab", { name: "Components" })).toHaveAttribute("aria-selected", "true");
    expect(screen.getByRole("heading", { name: "Buttons" })).toBeInTheDocument();
    fireEvent.click(screen.getByRole("tab", { name: "Tokens" }));

    const tokens = screen.getByRole("tab", { name: "Tokens" });
    tokens.focus();
    fireEvent.keyDown(tokens, { key: "ArrowRight" });
    expect(screen.getByRole("tab", { name: "Components" })).toHaveAttribute("aria-selected", "true");
    expect(screen.getByRole("heading", { name: "Buttons" })).toBeInTheDocument();

    const loadingButton = screen.getByRole("button", { name: "Click for loading" });
    fireEvent.click(loadingButton);
    expect(screen.getByRole("button", { name: "Working" })).toBeDisabled();
    act(() => vi.advanceTimersByTime(1_200));
    expect(screen.getByRole("button", { name: "Click for loading" })).toBeEnabled();

    const components = screen.getByRole("tab", { name: "Components" });
    fireEvent.keyDown(components, { key: "End" });
    expect(screen.getByRole("tab", { name: "States" })).toHaveAttribute("aria-selected", "true");
    expect(screen.getByText("The service returned a problem document.")).toBeInTheDocument();

    const states = screen.getByRole("tab", { name: "States" });
    fireEvent.keyDown(states, { key: "ArrowRight" });
    expect(screen.getByRole("tab", { name: "Tokens" })).toHaveAttribute("aria-selected", "true");
    fireEvent.keyDown(screen.getByRole("tab", { name: "Tokens" }), { key: "ArrowLeft" });
    expect(screen.getByRole("tab", { name: "States" })).toHaveAttribute("aria-selected", "true");
    fireEvent.keyDown(screen.getByRole("tab", { name: "States" }), { key: "Home" });
    expect(screen.getByRole("tab", { name: "Tokens" })).toHaveAttribute("aria-selected", "true");

    fireEvent.click(screen.getByRole("tab", { name: "Charts" }));
    expect(screen.getByLabelText("Sample algorithm mix")).toBeInTheDocument();
    expect(screen.getByLabelText("Sample rotation coverage")).toBeInTheDocument();

    fireEvent.keyDown(screen.getByRole("tab", { name: "Charts" }), { key: "Unrelated" });
    expect(screen.getByRole("tab", { name: "Charts" })).toHaveAttribute("aria-selected", "true");
  });
});
