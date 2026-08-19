import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import { PageHeader } from "@/components/PageHeader";
import { Button } from "@/components/ui/button";

describe("PageHeader", () => {
  it("bounds and wraps three long actions on mobile without shrinking their controls", async () => {
    const user = userEvent.setup();
    render(
      <PageHeader
        title="Certificates"
        actions={
          <>
            <Button variant="outline">Open CA hierarchy</Button>
            <Button variant="outline">Manage certificate profiles</Button>
            <Button>Request a new certificate</Button>
          </>
        }
      />,
    );

    expect(screen.getByRole("heading", { name: "Certificates" })).toBeVisible();
    const actions = screen.getByRole("group", { name: "Do next" });
    expect(actions).toBeInstanceOf(HTMLElement);
    expect(actions).toHaveClass("flex", "w-full", "min-w-0", "flex-wrap", "sm:w-auto", "sm:shrink-0");

    const buttons = screen.getAllByRole("button");
    expect(buttons).toHaveLength(3);
    for (const button of buttons) {
      expect(button).toHaveClass("h-9");
    }

    for (const button of buttons) {
      await user.tab();
      expect(button).toHaveFocus();
    }
  });

  it("orders plain outcome, real controls, and exact evidence as Answer, Operate, and Prove", () => {
    render(
      <PageHeader
        title="Certificates"
        description="See what is healthy and what expires soon."
        technicalDetails="Serials, renewal jobs, and audit events remain available."
        actions={<Button>Add certificate</Button>}
      />,
    );

    expect(screen.getByTestId("page-depth-answer")).toHaveTextContent("Answer");
    expect(screen.getByTestId("page-depth-answer")).toHaveTextContent("See what is healthy and what expires soon.");
    expect(screen.getByTestId("page-depth-operate")).toHaveTextContent("Do next");
    expect(screen.getByRole("button", { name: "Add certificate" })).toBeVisible();
    expect(screen.getByTestId("page-depth-prove")).toHaveTextContent("Technical details");
    expect(screen.getByTestId("page-depth-prove")).toHaveTextContent("Serials, renewal jobs, and audit events remain available.");
  });
});
