import { beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { AppQueryProvider } from "@/lib/query";
import { IntlProvider } from "@/i18n/I18nProvider";
import { OperationsLedgerPanel } from "@/pages/operations/OperationsLedgerPanel";
import { IdentityRevocationReport } from "@/pages/identities/IdentityRevocationReport";
import { OperationsDashboardPanel } from "@/pages/operations/OperationsDashboardPanel";

const { list, detail, report, dashboard } = vi.hoisted(() => ({ list: vi.fn(), detail: vi.fn(), report: vi.fn(), dashboard: vi.fn() }));
vi.mock("@/lib/api", async (original) => {
  const actual = await original<typeof import("@/lib/api")>();
  return {
    ...actual,
    api: { ...actual.api, operationLedger: list, operationLedgerItem: detail, identityRevocationReport: report, operationsDashboard: dashboard },
  };
});

const item = (id: string, state: string, source = "connector_delivery") => ({
  id,
  source,
  credential_type: "x509_certificate",
  subject: { id: "identity-1", name: "orders.example.test" },
  state,
  state_reason: `reason for ${state}`,
  source_status: state,
  created_at: "2030-01-01T10:00:00Z",
  updated_at: "2030-01-01T10:05:00Z",
});

function show(node: React.ReactNode) {
  return render(
    <MemoryRouter>
      <IntlProvider initialLocale="en-US" initialTimeZone="UTC">
        <AppQueryProvider>{node}</AppQueryProvider>
      </IntlProvider>
    </MemoryRouter>,
  );
}

describe("operations ledger (A245)", () => {
  beforeEach(() => {
    cleanup();
    list.mockReset();
    detail.mockReset();
    report.mockReset();
    dashboard.mockReset();
  });

  it("names agent jobs, ended sessions and managed-key operations as their own sources (A245-L1)", async () => {
    list.mockResolvedValue({
      items: [
        item("agent_job:41", "delivered", "agent_job"),
        item("access_session_revocation:00000000-0000-4000-8000-00000000a245", "uncertain", "access_session_revocation"),
        item("machine_session_revocation:ms-revoked-1", "verified", "machine_session_revocation"),
        item("managed_key_operation:op-rotate-1", "queued", "managed_key_operation"),
      ],
    });
    show(<OperationsLedgerPanel />);
    const region = within(await screen.findByRole("region", { name: "Operations ledger" }));
    await region.findByText("reason for uncertain");
    for (const label of ["Agent job", "Access session ended", "Machine session ended", "Managed key operation"]) {
      expect(region.getByText(label, { exact: false })).toBeInTheDocument();
    }
  });

  it("names an SSH certificate revocation as its own source (A245-L1)", async () => {
    list.mockResolvedValue({
      items: [item("ssh_certificate_revocation:krl-a245l1-1", "verified", "ssh_certificate_revocation")],
    });
    show(<OperationsLedgerPanel />);
    const region = within(await screen.findByRole("region", { name: "Operations ledger" }));
    await region.findByText("reason for verified");
    expect(region.getByText("SSH certificate revoked", { exact: false })).toBeInTheDocument();
  });

  it("shows each operation in its normalized state and filters by state", async () => {
    list.mockResolvedValue({
      items: [item("connector_delivery:a", "delivered"), item("connector_delivery:b", "failed"), item("secret_rotation:c", "verified", "secret_rotation")],
    });
    const user = userEvent.setup();
    show(<OperationsLedgerPanel />);
    const region = within(await screen.findByRole("region", { name: "Operations ledger" }));
    await region.findByText("reason for failed");
    const rows = region.getAllByRole("listitem").map((row) => row.textContent ?? "");
    expect(rows).toHaveLength(3);
    expect(rows[0]).toMatch(/^Delivered.*orders\.example\.test.*Delivery/);
    expect(rows[1]).toMatch(/^Failed/);
    expect(rows[2]).toMatch(/^Verified.*Secret rotation/);
    expect(list).toHaveBeenCalledWith({ limit: 50, state: undefined });
    await user.selectOptions(region.getByLabelText("State"), "failed");
    expect(list).toHaveBeenLastCalledWith({ limit: 50, state: "failed" });
  });

  it("opens one operation's causal chain and its scoped actions", async () => {
    list.mockResolvedValue({ items: [item("connector_delivery:b", "failed")] });
    detail.mockResolvedValue({
      ...item("connector_delivery:b", "failed"),
      chain: [
        { step: "request", state: "done", detail: "endpoint binding" },
        { step: "external_action", state: "failed", detail: "command 7: failed after 3 attempts" },
        { step: "observation", state: "not_observed", detail: "no consumer has confirmed it" },
      ],
      actions: [
        { action: "retry", available: true, scope: "deliver orders.example.test's active certificate to lb again", method: "POST", path: "/x" },
        { action: "rollback", available: false, scope: "restore the certificate lb held before this delivery", reason: "no predecessor was recorded" },
      ],
    });
    const user = userEvent.setup();
    show(<OperationsLedgerPanel />);
    await user.click(await screen.findByRole("button", { name: "Details" }));
    expect(await screen.findByText(/command 7: failed after 3 attempts/)).toBeInTheDocument();
    expect(detail).toHaveBeenCalledWith("connector_delivery:b");
    expect(screen.getByText(/Available: deliver orders.example.test's active certificate to lb again/)).toBeInTheDocument();
    expect(screen.getByText(/restore the certificate lb held before this delivery — no predecessor was recorded/)).toBeInTheDocument();
  });

  it("keeps the four revocation facets apart", async () => {
    const facet = (state: string, detail: string) => ({ state, detail });
    report.mockResolvedValue({
      identity_id: "identity-1",
      certificates: [
        {
          certificate_id: "c1",
          serial: "0a0b",
          fingerprint: "f",
          revoked_at: "2030-01-01T12:00:00Z",
          ca_status: facet("confirmed", "OCSP answers revoked, and CRL #7 lists it"),
          deployed_material: facet("pending", "1 of 1 destinations still hold it"),
          new_connections: facet("failed", "1 of 1 checked endpoints still present it to new connections"),
          existing_sessions: facet("not_observed", "sessions opened before the revocation are not observed"),
          destinations: [{ target: "lb", state: "pending", now: "still_deployed", at: "2030-01-01T12:00:00Z" }],
          endpoints: [
            { endpoint_id: "edge", vantage: "relay", state: "failed", detail: "still presents the revoked certificate", checked_at: "2030-01-01T12:30:00Z" },
          ],
        },
      ],
    });
    show(<IdentityRevocationReport identityId="identity-1" />);
    const region = within(await screen.findByRole("region", { name: "Revocation report" }));
    await region.findByText("OCSP answers revoked, and CRL #7 lists it");
    expect(region.getByText("Confirmed")).toBeInTheDocument();
    expect(region.getByText("Pending")).toBeInTheDocument();
    expect(region.getByText("Failed")).toBeInTheDocument();
    expect(region.getByText("Not observed")).toBeInTheDocument();
    expect(region.getByText("lb: still holds it")).toBeInTheDocument();
    expect(region.getByText("edge (relay): still presents the revoked certificate")).toBeInTheDocument();
  });

  it("shows deployment health with the numbers behind each state (A246)", async () => {
    dashboard.mockResolvedValue({
      generated_at: "2030-01-01T12:00:00Z",
      backup: {
        state: "warning",
        detail: "the newest backup is more than a day old",
        configured: true,
        verified: true,
        last_backup_at: "2029-12-31T06:00:00Z",
        age_seconds: 108000,
      },
      restore_proof: { state: "ok", detail: "restored", outcome: "restored", completed_at: "2029-12-31T07:00:00Z", rpo_seconds: 600, rto_seconds: 1200 },
      queues: { state: "critical", detail: "a worker's lease ran out", pending: 4, processing: 1, stranded: 1, failed: 0 },
      signer: { state: "ok", detail: "the signer answers its readiness probe", healthy: true },
      data_freshness: { state: "ok", detail: "current", event_head: 120, projection_applied: 118, lag_events: 2 },
      dependencies: [
        { name: "db", healthy: true },
        { name: "nats", healthy: false, detail: "event log unreachable" },
      ],
    });
    show(<OperationsDashboardPanel />);
    const region = within(await screen.findByRole("region", { name: "Deployment health" }));
    await region.findByText("4 waiting, 1 running, 1 stranded, 0 failed");
    expect(region.getByText("Log head 120; read model at 118 (2 behind)")).toBeInTheDocument();
    expect(region.getByText("nats: event log unreachable")).toBeInTheDocument();
    expect(region.getByText("db: healthy")).toBeInTheDocument();
    expect(region.getByText(/^Newest backup taken /)).toBeInTheDocument();
    expect(region.getByText(/^Last drill .+: RPO 600 s, RTO 1200 s$/)).toBeInTheDocument();
    expect(region.getAllByText("Critical").length).toBeGreaterThan(0);
  });
});
