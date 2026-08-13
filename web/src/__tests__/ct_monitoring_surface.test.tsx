import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { CTMonitoringPanel } from "@/components/discovery";
import { api } from "@/lib/api";

// C5: certificate transparency as a headline discovery capability.
//
// The backend has polled RFC 6962 logs for a while. What it lacked was a place
// an operator would look: on Discovery it was one number in a tile shared with
// drift detection, the watchlist lived on another page, and the question the
// feature answers — "is someone issuing certificates for my domains?" — was not
// asked anywhere on the page. These assert the whole loop is on one surface, and
// that the surface states what it does not cover.

vi.mock("@/components/rbac", () => ({ useCan: () => true }));

const monitoring = {
  capability: "ct_log",
  findings_path: "/api/v1/discovery/findings",
  runs_path: "/api/v1/discovery/runs",
  sources_path: "/api/v1/discovery/sources",
  watchlist_path: "/api/v1/discovery/ct-monitoring",
  notification_destination: "notification.ct",
  outbox_backed_alerts: true,
  watched_domains: ["example.test"],
  logs: [
    { url: "https://ct.example.test/log-a", next_index: 4211, status: "succeeded", last_polled_at: "2026-08-01T01:00:00Z" },
    { url: "https://ct.example.test/log-b", next_index: 0, status: "failed", last_error: "get-sth returned 503" },
  ],
  retired_logs: [
    {
      url: "https://ct.example.test/obsolete",
      next_index: 17,
      status: "failed",
      last_error: "get-sth returned 404",
      retired_at: "2026-08-01T02:00:00Z",
    },
  ],
  summary: {
    finding_count: 1,
    log_count: 2,
    retired_log_count: 1,
    failed_log_count: 1,
    open_finding_count: 1,
    outbox_alert_channel_count: 2,
    source_count: 1,
    unexpected_issuance_count: 1,
    watched_domain_count: 1,
  },
  findings: [
    {
      id: "f1",
      kind: "ct_unexpected_issuance",
      ref: "shadow.example.test",
      source_id: "s1",
      run_id: "r1",
      provenance: "ct_log",
      discovered_at: "2026-08-01T00:00:00Z",
      fingerprint: "sha256:rogue",
      metadata: { subject: "shadow.example.test", issuer: "CN=Some Public CA" },
    },
  ],
};

function renderPanel(props: React.ComponentProps<typeof CTMonitoringPanel> = {}) {
  return render(
    <MemoryRouter>
      <CTMonitoringPanel {...props} />
    </MemoryRouter>,
  );
}

describe("C5 certificate transparency monitoring surface", () => {
  beforeEach(() => {
    vi.spyOn(api, "ctMonitoring").mockResolvedValue(monitoring as never);
    vi.spyOn(api, "updateCTMonitoring").mockResolvedValue({ ...monitoring, run: { id: "run-9", status: "queued" } } as never);
    vi.spyOn(api, "getDiscoveryRun").mockResolvedValue({ id: "run-9", status: "succeeded" } as never);
  });

  it("shows the watchlist, per-log checkpoint state, and unexpected issuance on one surface", async () => {
    renderPanel();

    expect(await screen.findByText("Certificate Transparency monitoring")).toBeInTheDocument();

    // Per-log checkpoint state: success and failure must read differently.
    // "Configured" is not the same as "working".
    expect(await screen.findByText("https://ct.example.test/log-a")).toBeInTheDocument();
    expect(screen.getByText(/last poll succeeded.*next index 4211/i)).toBeInTheDocument();
    expect(screen.getByText(/last poll failed.*next index 0/i)).toBeInTheDocument();
    expect(screen.getByText("Last error: get-sth returned 503")).toBeInTheDocument();

    // Removed logs remain audit-readable but are visibly outside active polling.
    expect(screen.getByText("Retired log history (not polled)")).toBeInTheDocument();
    expect(screen.getByText("https://ct.example.test/obsolete")).toBeInTheDocument();
    expect(screen.getByText(/last poll failed.*next index 17/i)).toBeInTheDocument();
    expect(screen.getByText("Last error: get-sth returned 404")).toBeInTheDocument();

    // The finding, with enough certificate detail to act on.
    expect(screen.getByText("shadow.example.test")).toBeInTheDocument();
    expect(screen.getByText("CN=Some Public CA")).toBeInTheDocument();

    // And the hand-off: detection is here, remediation already has a home.
    expect(screen.getByRole("link", { name: "Investigate" })).toHaveAttribute("href", "/certificates?view=rogue");
  });

  it("states what it does not cover, so an empty list is not read as an all-clear", async () => {
    renderPanel();
    const honesty = await screen.findByText(/covers only the domains and logs configured/i);
    expect(honesty).toBeInTheDocument();
    expect(honesty.textContent).toMatch(/not automatic estate-wide/i);
  });

  it("configures the watchlist and queues a run from the same surface", async () => {
    const user = userEvent.setup();
    renderPanel();

    const domains = await screen.findByRole("textbox", { name: "Watched domains" });
    await user.clear(domains);
    await user.type(domains, "example.test\npayments.example.test");
    await user.click(screen.getByRole("button", { name: "Save and run now" }));

    await waitFor(() => expect(api.updateCTMonitoring).toHaveBeenCalled());
    const sent = vi.mocked(api.updateCTMonitoring).mock.calls[0][0] as { watched_domains: string[]; run_now: boolean };
    expect(sent.watched_domains).toEqual(["example.test", "payments.example.test"]);
    // "Save" alone would leave the operator waiting on the next schedule to find
    // out whether their watchlist works.
    expect(sent.run_now).toBe(true);
    expect(await screen.findByText("run run-9 succeeded")).toBeInTheDocument();
  });

  it("AUD-71 follows parent refresh authority without a remount", async () => {
    const first = monitoring;
    const refreshed = {
      ...monitoring,
      logs: [{ ...monitoring.logs[0], next_index: 5000 }],
    };
    vi.mocked(api.ctMonitoring)
      .mockReset()
      .mockResolvedValueOnce(first as never)
      .mockResolvedValueOnce(refreshed as never);

    const view = renderPanel({ refreshToken: 0 });
    expect(await screen.findByText(/next index 4211/i)).toBeInTheDocument();

    view.rerender(
      <MemoryRouter>
        <CTMonitoringPanel refreshToken={1} />
      </MemoryRouter>,
    );
    expect(await screen.findByText(/next index 5000/i)).toBeInTheDocument();
    expect(api.ctMonitoring).toHaveBeenCalledTimes(2);
  });

  it("AUD-71 polls an active run to terminal and refreshes mixed-log checkpoints in place", async () => {
    const user = userEvent.setup();
    const terminal = {
      ...monitoring,
      run: { id: "run-9", status: "partial", error: "1 of 2 CT logs failed: get-sth returned 503" },
      logs: [
        { ...monitoring.logs[0], next_index: 4250, status: "succeeded" },
        { ...monitoring.logs[1], next_index: 0, status: "failed", last_error: "get-sth returned 503" },
      ],
    };
    vi.mocked(api.ctMonitoring)
      .mockReset()
      .mockResolvedValueOnce(monitoring as never)
      .mockResolvedValueOnce(terminal as never);
    vi.mocked(api.getDiscoveryRun)
      .mockReset()
      .mockResolvedValueOnce({ id: "run-9", status: "running" } as never)
      .mockResolvedValueOnce(terminal.run as never);
    const onRunTerminal = vi.fn().mockResolvedValue(undefined);
    renderPanel({ pollIntervalMs: 5, onRunTerminal });

    await screen.findByText(/next index 4211/i);
    await user.click(screen.getByRole("button", { name: "Save and run now" }));

    expect(await screen.findByText(/next index 4250/i)).toBeInTheDocument();
    expect(api.getDiscoveryRun).toHaveBeenCalledTimes(2);
    await waitFor(() => expect(onRunTerminal).toHaveBeenCalledWith(expect.objectContaining({ id: "run-9", status: "partial" })));
    expect(screen.getByText("Last error: get-sth returned 503")).toBeInTheDocument();
  });

  it("AUD-71 cancels active-run polling when the panel unmounts", async () => {
    const user = userEvent.setup();
    vi.mocked(api.getDiscoveryRun)
      .mockReset()
      .mockResolvedValue({ id: "run-9", status: "running" } as never);
    const view = renderPanel({ pollIntervalMs: 5 });
    await screen.findByText(/next index 4211/i);
    await user.click(screen.getByRole("button", { name: "Save and run now" }));
    await waitFor(() => expect(api.getDiscoveryRun).toHaveBeenCalled());
    view.unmount();
    const callsAtUnmount = vi.mocked(api.getDiscoveryRun).mock.calls.length;

    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(api.getDiscoveryRun).toHaveBeenCalledTimes(callsAtUnmount);
  });
});
