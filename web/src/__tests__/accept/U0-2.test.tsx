import { describe, it, expect } from "vitest";
import { render, screen, within } from "@testing-library/react";
import { axe } from "vitest-axe";
import { DashboardGrid, SectionCard, AttentionList, AttentionRow } from "@/components/dashboard";
import { StatTile } from "@/components/charts";

describe("U0-2 dashboard primitives", () => {
  it("renders a KPI grid of stat tiles", () => {
    render(
      <DashboardGrid>
        <StatTile label="Total certificates" value={1284} />
        <StatTile label="Expiring within 30 days" value={47} tone="warning" />
      </DashboardGrid>,
    );
    expect(screen.getByText("Total certificates")).toBeInTheDocument();
    expect(screen.getByText("47")).toBeInTheDocument();
  });

  it("renders a section card with heading, description, and an attention list", async () => {
    const { container } = render(
      <SectionCard title="Needs attention" description="Certificates that need a human">
        <AttentionList ariaLabel="Certificates needing attention">
          <AttentionRow>
            <span>api.payments.acme.com</span>
            <span>4d left</span>
          </AttentionRow>
        </AttentionList>
      </SectionCard>,
    );
    expect(screen.getByRole("heading", { name: "Needs attention" })).toBeInTheDocument();
    expect(screen.getByText("Certificates that need a human")).toBeInTheDocument();
    const list = screen.getByRole("list", { name: "Certificates needing attention" });
    expect(within(list).getByText("api.payments.acme.com")).toBeInTheDocument();
    expect(await axe(container)).toHaveNoViolations();
  });
});
