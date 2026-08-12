import { render, screen, within } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { ADCSTemplatePanel } from "@/components/posture/ADCSTemplatePanel";
import { AppQueryProvider } from "@/lib/query";

const { apiMock } = vi.hoisted(() => ({ apiMock: { adcsPosture: vi.fn() } }));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...apiMock } };
});

describe("AD CS inventory posture", () => {
  beforeEach(() => {
    apiMock.adcsPosture.mockReset().mockResolvedValue({
      observed: true,
      sources: [
        {
          source_id: "11111111-1111-4111-8111-111111111111",
          name: "corp-adcs",
          schedule_enabled: true,
          monitoring_interval_seconds: 3600,
          last_run_id: "22222222-2222-4222-8222-222222222222",
          last_run_status: "failed",
          last_run_error: "directory_authentication_failed",
          last_run_created_at: "2026-08-11T23:45:00Z",
        },
      ],
      templates: [
        {
          domain: "CORP-CA",
          template: "UserAuth",
          display_name: "User Authentication",
          enrollment_principals: ["S-1-5-11", "S-1-5-21-111-222-333-1001"],
          published_by: ["CORP-CA"],
          worst_severity: "",
          findings: [],
          observed_at: "2026-08-11T23:40:00Z",
          observed_by: "network-relay-1",
        },
      ],
      critical: 0,
      high: 0,
      medium: 0,
      guidance: "Enrollment trustees are canonical SIDs; verify effective directory access before changing policy.",
    });
  });

  it("shows source failure lifecycle and enrollment trustees in the shared data grid", async () => {
    render(
      <AppQueryProvider>
        <ADCSTemplatePanel />
      </AppQueryProvider>,
    );

    expect(await screen.findByRole("list", { name: "Sources" })).toBeInTheDocument();
    expect(screen.getByText("corp-adcs")).toBeInTheDocument();
    expect(screen.getByText("Failed")).toHaveAttribute("data-status-value", "failed");
    expect(screen.getByText("directory_authentication_failed")).toBeInTheDocument();

    const grid = screen.getByRole("table", { name: "AD CS certificate templates" });
    expect(within(grid).getByRole("columnheader", { name: "Principal" })).toBeInTheDocument();
    expect(within(grid).getByText("S-1-5-11, S-1-5-21-111-222-333-1001")).toBeInTheDocument();
    expect(screen.queryByText(/not yet decoded/i)).not.toBeInTheDocument();
  });
});
