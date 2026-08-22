import { render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { StepShell } from "@/components/wizard/StepShell";

const steps = Array.from({ length: 6 }, (_, index) => ({
  id: `step-${index + 1}`,
  label: `Decision ${index + 1}`,
  description: `Why decision ${index + 1} matters.`,
}));

describe("StepShell quiet mobile progress", () => {
  it("shows only the previous, current, and next decision in the compact progress view", () => {
    render(
      <StepShell steps={steps} currentIndex={3} onNext={() => undefined} onPrevious={() => undefined}>
        <p>Current task</p>
      </StepShell>,
    );

    const compact = screen.getByTestId("compact-step-progress");
    expect(within(compact).getAllByRole("listitem")).toHaveLength(3);
    expect(compact).toHaveTextContent("Decision 3");
    expect(compact).toHaveTextContent("Decision 4");
    expect(compact).toHaveTextContent("Decision 5");
    expect(compact).not.toHaveTextContent("Decision 1");
    expect(compact).not.toHaveTextContent("Decision 6");
    const current = within(compact).getByText("Decision 4").closest("li");
    expect(current).toHaveAttribute("aria-current", "step");
    expect(current).toHaveClass("text-foreground");

    const full = screen.getByTestId("full-step-progress");
    const fullCurrent = within(full).getByText("Decision 4").closest("li");
    expect(fullCurrent?.firstElementChild).toHaveClass("text-foreground");
    expect(fullCurrent?.firstElementChild).not.toHaveClass("text-brand-accent");
  });
});
