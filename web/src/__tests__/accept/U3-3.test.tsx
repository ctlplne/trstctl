import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { RiskPosture } from "@/components/risk/posture";
import type { UrgentRiskSummary } from "@/lib/api";

const summary = {
  status: "complete",
  scope: "All served credential-risk and contextual-priority projections for this tenant; totals deduplicate credential_id.",
  included_projections: ["credential_risk_scores", "contextual_priorities"],
  unique_analyzed: 2,
  urgent: 1,
  critical: 1,
  high: 0,
  credential_risk: { analyzed: 2, critical: 1, high: 0 },
  contextual_priorities: { analyzed: 2, critical: 1, high: 0 },
} as UrgentRiskSummary;

describe("U3-3 risk posture dashboard", () => {
  it("summarizes the deduplicated all-projection contract and exposes each source count", () => {
    render(<RiskPosture summary={summary} loading={false} error={null} />);
    expect(screen.getByText("Unique credentials analyzed")).toBeInTheDocument();
    expect(screen.getByText("Critical urgent")).toBeInTheDocument();
    expect(screen.getByText("Credential-score projection")).toBeInTheDocument();
    expect(screen.getByText("Contextual projection")).toBeInTheDocument();
    expect(screen.getByText(summary.scope)).toBeInTheDocument();
  });

  it("renders a missing authority as unavailable instead of a safe zero", () => {
    render(<RiskPosture summary={null} loading={false} error="contextual projection failed" />);
    expect(screen.getByText("Urgent risk summary unavailable")).toBeInTheDocument();
    expect(screen.getByText("contextual projection failed")).toBeInTheDocument();
    expect(screen.queryByText("0")).not.toBeInTheDocument();
  });
});
