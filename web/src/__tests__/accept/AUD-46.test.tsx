import { render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { CMDBSyncPanel } from "@/components/CMDBSyncPanel";
import { AppQueryProvider } from "@/lib/query";

const { cmdbSchedule } = vi.hoisted(() => ({ cmdbSchedule: vi.fn() }));

vi.mock("@/lib/api", async (original) => {
  const actual = await original<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, cmdbSchedule } };
});

function renderPanel() {
  return render(
    <AppQueryProvider>
      <CMDBSyncPanel />
    </AppQueryProvider>,
  );
}

describe("AUD-46 bounded CMDB coverage", () => {
  beforeEach(() => cmdbSchedule.mockReset());

  it("keeps a full first page visibly incomplete with its durable denominator", async () => {
    cmdbSchedule.mockResolvedValue({
      configured: true,
      enabled: true,
      execution: "relay",
      interval_seconds: 3600,
      sweep_id: "11111111-1111-4111-8111-111111111111",
      next_cursor: "ci-0500",
      read_count: 500,
      expected_count: 501,
      pages_completed: 1,
      coverage_complete: false,
      coverage_status: "in_progress",
      changed_count: 0,
      removed_count: 0,
      guidance: "Read-only relay reconciliation.",
    });
    renderPanel();

    const status = await screen.findByRole("status");
    expect(status).toHaveTextContent("500 of 501 CIs read across 1 pages");
    expect(status).toHaveTextContent("Coverage incomplete. The committed cursor ci-0500");
    expect(screen.queryByText("Enabled, and has not read the CMDB yet.")).not.toBeInTheDocument();
  });

  it("calls only the short terminal page complete and serves change/removal evidence", async () => {
    cmdbSchedule.mockResolvedValue({
      configured: true,
      enabled: true,
      execution: "relay",
      interval_seconds: 3600,
      last_run_at: "2026-08-12T20:00:00Z",
      sweep_id: "22222222-2222-4222-8222-222222222222",
      next_cursor: "ci-0501",
      read_count: 501,
      expected_count: 501,
      pages_completed: 2,
      coverage_complete: true,
      coverage_status: "complete",
      changed_count: 3,
      removed_count: 2,
      guidance: "Read-only relay reconciliation.",
    });
    renderPanel();

    const status = await screen.findByRole("status");
    expect(status).toHaveTextContent("501 of 501 CIs read across 2 pages");
    expect(status).toHaveTextContent("Coverage complete. 3 changed and 2 removed CIs reconciled.");
    expect(screen.queryByText(/Coverage incomplete/)).not.toBeInTheDocument();
  });
});
