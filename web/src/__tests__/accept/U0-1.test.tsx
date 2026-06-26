import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { axe } from "vitest-axe";
import { StatTile, Meter, BucketBar, Donut, Sparkline } from "@/components/charts";

describe("U0-1 dataviz primitives", () => {
  it("renders a KPI stat tile with label, value, and hint", () => {
    render(<StatTile label="Total certificates" value={1284} hint="across all tenants" tone="brand" />);
    expect(screen.getByText("Total certificates")).toBeInTheDocument();
    expect(screen.getByText("1284")).toBeInTheDocument();
    expect(screen.getByText("across all tenants")).toBeInTheDocument();
  });

  it("renders each chart primitive with an accessible role and label", () => {
    render(
      <div>
        <Meter
          ariaLabel="Renewal mode split"
          segments={[
            { value: 62, tone: "success", label: "auto" },
            { value: 38, tone: "warning", label: "manual" },
          ]}
        />
        <BucketBar
          ariaLabel="Certificates by time to expiry"
          data={[
            { label: "<=7d", value: 9, tone: "critical" },
            { label: "<=30d", value: 35, tone: "warning" },
            { label: "90d+", value: 1117, tone: "low" },
          ]}
        />
        <Donut
          ariaLabel="Certificates by algorithm"
          segments={[
            { value: 60, tone: "low", label: "ECDSA" },
            { value: 40, tone: "medium", label: "RSA" },
          ]}
        />
        <Sparkline ariaLabel="Issuance trend" points={[3, 5, 4, 8, 6, 9]} />
      </div>,
    );
    expect(screen.getByRole("img", { name: "Renewal mode split" })).toBeInTheDocument();
    expect(screen.getByRole("img", { name: "Certificates by time to expiry" })).toBeInTheDocument();
    expect(screen.getByRole("img", { name: "Certificates by algorithm" })).toBeInTheDocument();
    expect(screen.getByRole("img", { name: "Issuance trend" })).toBeInTheDocument();
  });

  it("draws bucket bars from real values (no fixtures) and has no a11y violations", async () => {
    const { container } = render(
      <div>
        <StatTile label="Expiring within 30 days" value={47} tone="warning" />
        <BucketBar ariaLabel="Expiry buckets" data={[{ label: "<=7d", value: 9, tone: "critical" }]} />
      </div>,
    );
    expect(screen.getByText("47")).toBeInTheDocument();
    expect(screen.getByText("9")).toBeInTheDocument();
    expect(await axe(container)).toHaveNoViolations();
  });
});
