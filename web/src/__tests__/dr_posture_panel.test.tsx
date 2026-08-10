import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { DRPosturePanel } from "@/components/DRPosturePanel";

describe("full-set disaster recovery evidence", () => {
  it("renders the recovered row count, full predicate detail, and delivered artifacts", () => {
    render(
      <DRPosturePanel
        error={null}
        formatPolicy={{ locale: "en-US", timeZone: "UTC" }}
        posture={{
          backup_configured: true,
          verified: true,
          artifacts_checked: 5,
          artifacts_unverifiable: 0,
          detail: "The backup verified.",
          guidance: "Verify and restore.",
          last_drill: {
            outcome: "restored",
            ran_at: "2026-08-09T18:00:00Z",
            rpo_seconds: 60,
            rto_seconds: 9,
            events_restored: 3,
            postgres_records_restored: 27,
            postgres_tables_restored: { provider_tenants: 1 },
            artifacts_restored: ["event-log", "postgres-state", "signer-keystore"],
            full_set_restored: true,
            store_healthy: true,
            event_log_healthy: true,
            signer_healthy: true,
            server_healthy: true,
            detail: "The complete backup set restored and every recovered health check passed.",
            limitations: ["The measured RTO is a floor."],
          },
        }}
      />,
    );

    expect(screen.getByText("27")).toBeInTheDocument();
    expect(screen.getByText("The complete backup set restored and every recovered health check passed.")).toBeInTheDocument();
    expect(screen.getByText("event-log · postgres-state · signer-keystore")).toBeInTheDocument();
  });
});
