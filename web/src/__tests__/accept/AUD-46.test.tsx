import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { CMDBSyncPanel } from "@/components/CMDBSyncPanel";
import { RbacProvider } from "@/components/rbac";
import { AppQueryProvider } from "@/lib/query";

const { cmdbSchedule, putCMDBSchedule } = vi.hoisted(() => ({ cmdbSchedule: vi.fn(), putCMDBSchedule: vi.fn() }));

vi.mock("@/lib/api", async (original) => {
  const actual = await original<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, cmdbSchedule, putCMDBSchedule } };
});

function renderPanel(permissions: string[] | null = null) {
  return render(
    <AppQueryProvider>
      <RbacProvider permissions={permissions}>
        <CMDBSyncPanel />
      </RbacProvider>
    </AppQueryProvider>,
  );
}

describe("AUD-46 bounded CMDB coverage", () => {
  beforeEach(() => {
    cmdbSchedule.mockReset();
    putCMDBSchedule.mockReset();
  });

  it("configures an unconfigured relay schedule only after reviewing the exact approved binding", async () => {
    cmdbSchedule.mockResolvedValue({ configured: false, enabled: false, coverage_status: "not_configured", guidance: "" });
    putCMDBSchedule.mockResolvedValue({ configured: true, enabled: true, execution: "relay" });
    const user = userEvent.setup();
    renderPanel();

    await user.click(await screen.findByRole("button", { name: "Configure CMDB sync" }));
    await user.type(screen.getByRole("textbox", { name: "Approved ServiceNow URL" }), "https://servicenow.qa.local:18080");
    await user.type(screen.getByRole("textbox", { name: "Secret reference" }), "secret://qa/servicenow-token");
    await user.type(screen.getByRole("textbox", { name: "CI query" }), "install_status=1");
    await user.clear(screen.getByRole("spinbutton", { name: "Interval in seconds" }));
    await user.type(screen.getByRole("spinbutton", { name: "Interval in seconds" }), "3600");
    await user.click(screen.getByRole("checkbox", { name: "Enable scheduled reads" }));
    await user.click(screen.getByRole("button", { name: "Review CMDB schedule" }));

    expect(putCMDBSchedule).not.toHaveBeenCalled();
    expect(screen.getByRole("region", { name: "Reviewed CMDB schedule" })).toHaveTextContent("secret://qa/servicenow-token");
    await user.click(screen.getByRole("button", { name: "Save reviewed CMDB schedule" }));
    await waitFor(() =>
      expect(putCMDBSchedule).toHaveBeenCalledWith(
        {
          instance_url: "https://servicenow.qa.local:18080",
          token_ref: "secret://qa/servicenow-token",
          ci_query: "install_status=1",
          interval_seconds: 3600,
          enabled: true,
          execution: "relay",
          allow_private_endpoint: false,
        },
        expect.any(String),
      ),
    );
  });

  it("refuses an HTTP relay URL before review because operator bindings require HTTPS", async () => {
    cmdbSchedule.mockResolvedValue({ configured: false, enabled: false, coverage_status: "not_configured", guidance: "" });
    const user = userEvent.setup();
    renderPanel();

    await user.click(await screen.findByRole("button", { name: "Configure CMDB sync" }));
    await user.type(screen.getByRole("textbox", { name: "Approved ServiceNow URL" }), "http://127.0.0.1:18080");
    await user.type(screen.getByRole("textbox", { name: "Secret reference" }), "secret://qa/servicenow-token");
    await user.click(screen.getByRole("button", { name: "Review CMDB schedule" }));

    expect(await screen.findByRole("alert")).toHaveTextContent("HTTPS");
    expect(screen.queryByRole("region", { name: "Reviewed CMDB schedule" })).not.toBeInTheDocument();
    expect(putCMDBSchedule).not.toHaveBeenCalled();
  });

  it("keeps the reviewed idempotency key after an uncertain save response", async () => {
    cmdbSchedule.mockResolvedValue({ configured: false, enabled: false, coverage_status: "not_configured", guidance: "" });
    putCMDBSchedule.mockRejectedValueOnce(new Error("response lost")).mockResolvedValueOnce({ configured: true, enabled: false });
    const user = userEvent.setup();
    renderPanel();

    await user.click(await screen.findByRole("button", { name: "Configure CMDB sync" }));
    await user.type(screen.getByRole("textbox", { name: "Approved ServiceNow URL" }), "https://servicenow.qa.local");
    await user.type(screen.getByRole("textbox", { name: "Secret reference" }), "secret://qa/servicenow-token");
    await user.click(screen.getByRole("button", { name: "Review CMDB schedule" }));
    await user.click(screen.getByRole("button", { name: "Save reviewed CMDB schedule" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("response lost");
    await user.click(screen.getByRole("button", { name: "Save reviewed CMDB schedule" }));
    await waitFor(() => expect(putCMDBSchedule).toHaveBeenCalledTimes(2));
    expect(putCMDBSchedule.mock.calls[1][1]).toBe(putCMDBSchedule.mock.calls[0][1]);
  });

  it("does not offer schedule writes to a read-only owner", async () => {
    cmdbSchedule.mockResolvedValue({ configured: false, enabled: false, coverage_status: "not_configured", guidance: "" });
    renderPanel(["owners:read"]);

    expect(await screen.findByText("No ServiceNow CMDB schedule is configured.")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Configure CMDB sync" })).not.toBeInTheDocument();
  });

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
