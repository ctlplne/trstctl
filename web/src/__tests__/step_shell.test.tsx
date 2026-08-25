import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import { StepShell } from "@/components/wizard/StepShell";

const steps = Array.from({ length: 6 }, (_, index) => ({
  id: `step-${index + 1}`,
  label: `Decision ${index + 1}`,
  description: `Why decision ${index + 1} matters.`,
}));

describe("StepShell quiet mobile progress", () => {
  it("shows only the nearby decision path until the user asks for every step", async () => {
    const user = userEvent.setup();
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
    expect(screen.getByRole("progressbar", { name: "Onboarding progress" })).toHaveAttribute("aria-valuenow", "67");

    const full = screen.getByTestId("full-step-progress");
    expect(full).not.toHaveAttribute("open");
    await user.click(within(full).getByText("View all setup steps"));
    expect(full).toHaveAttribute("open");
    const fullCurrent = within(full).getByText("Decision 4").closest("li");
    expect(fullCurrent?.firstElementChild).toHaveClass("text-foreground");
    expect(fullCurrent?.firstElementChild).not.toHaveClass("text-brand-accent");
  });

  it("uses explicit evidence progress when browsing a long-lived journey", () => {
    const evidenceSteps = steps.map((step, index) => ({
      ...step,
      progressState: (index === 0 ? "blocked" : "pending") as "blocked" | "pending",
    }));
    render(
      <StepShell steps={evidenceSteps} currentIndex={1} progressLabel="Verified journey progress" onNext={() => undefined} onPrevious={() => undefined}>
        <p>Current journey step</p>
      </StepShell>,
    );

    const progress = screen.getByRole("progressbar", { name: "Verified journey progress" });
    expect(progress).toHaveAttribute("aria-valuenow", "0");
    const compact = screen.getByTestId("compact-step-progress");
    expect(compact).toHaveTextContent("!");
    expect(compact).not.toHaveTextContent("✓");
  });
});
