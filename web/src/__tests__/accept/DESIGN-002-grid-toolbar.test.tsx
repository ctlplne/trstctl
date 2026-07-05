import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { ToastProvider } from "@/components/ToastProvider";
import { Certificates } from "@/pages/Certificates";
import { Discovery } from "@/pages/Discovery";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    certificatePage: vi.fn(),
    getCertificate: vi.fn(),
    ingestCertificate: vi.fn(),
    certificateHealth: vi.fn(),
    crlDistributions: vi.fn(),
    owners: vi.fn(),
    risk: vi.fn(),
    rotationRuns: vi.fn(),
    connectorDeliveries: vi.fn(),
    discoverySources: vi.fn(),
    discoverySchedules: vi.fn(),
    discoveryRuns: vi.fn(),
    discoveryMonitoring: vi.fn(),
    nhiShadowPosture: vi.fn(),
    discoveryFindings: vi.fn(),
    claimDiscoveryFinding: vi.fn(),
    dismissDiscoveryFinding: vi.fn(),
    createDiscoverySource: vi.fn(),
    createDiscoverySchedule: vi.fn(),
    startDiscoveryRun: vi.fn(),
  },
}));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...apiMock } };
});

function renderCertificates() {
  return render(
    <MemoryRouter initialEntries={["/certificates"]}>
      <ToastProvider>
        <Certificates />
      </ToastProvider>
    </MemoryRouter>,
  );
}

function renderDiscovery() {
  return render(
    <MemoryRouter initialEntries={["/discovery"]}>
      <ToastProvider>
        <Discovery />
      </ToastProvider>
    </MemoryRouter>,
  );
}

describe("DESIGN-002 dense grid and toolbar consistency", () => {
  beforeEach(() => {
    localStorage.clear();
    vi.restoreAllMocks();
    for (const mock of Object.values(apiMock)) mock.mockReset();
    seedCertificateMocks();
    seedDiscoveryMocks();
  });

  it("serves certificate inventory through the shared grid toolbar with saved views and a column chooser", async () => {
    const user = userEvent.setup();
    renderCertificates();

    expect(await screen.findByText("CN=payments.example.test")).toBeInTheDocument();
    const grid = screen.getByLabelText("Inventoried certificates");
    expect(within(grid).getByRole("searchbox", { name: "Search loaded rows" })).toBeInTheDocument();
    expect(within(grid).getByRole("button", { name: "Columns" })).toBeInTheDocument();
    expect(within(grid).getByRole("button", { name: "Save view" })).toBeDisabled();

    await user.selectOptions(within(grid).getByLabelText("Team filter"), "team-platform");
    await user.type(within(grid).getByLabelText("Saved view name"), "Prod web");
    await user.click(within(grid).getByRole("button", { name: "Save view" }));

    const stored = localStorage.getItem("trstctl-grid-view:certificates-inventory") ?? "";
    expect(stored).toContain("Prod web");
    expect(stored).toContain("team-platform");
    expect(stored).not.toContain("Platform Team");
    expect(stored).not.toContain("CN=payments.example.test");
    expect(stored).not.toContain("sha256:pay");
  });

  it("serves discovery monitoring, source, schedule, run, and finding tables through the shared grid controls", async () => {
    const user = userEvent.setup();
    renderDiscovery();

    expect(await screen.findByRole("heading", { name: "Discovery" })).toBeInTheDocument();
    // Each surface lives on its workspace tab; monitoring + findings share the default tab.
    const surfaces: Array<{ heading: string; tab?: string }> = [
      { heading: "Continuous monitoring" },
      { heading: "Findings" },
      { heading: "Sources", tab: "Sources" },
      { heading: "Schedules", tab: "Schedules" },
      { heading: "Runs", tab: "Runs" },
    ];
    for (const surface of surfaces) {
      if (surface.tab) await user.click(screen.getByRole("tab", { name: surface.tab }));
      const section = screen.getByRole("heading", { name: surface.heading }).closest("section");
      expect(section).toBeTruthy();
      expect(within(section as HTMLElement).getByRole("button", { name: "Columns" })).toBeInTheDocument();
      expect(within(section as HTMLElement).getByRole("button", { name: "Save view" })).toBeInTheDocument();
    }

    await user.click(screen.getByRole("tab", { name: "Findings" }));
    const findings = screen.getByRole("heading", { name: "Findings" }).closest("section") as HTMLElement;
    expect(within(findings).getByLabelText("Triage status")).toBeInTheDocument();
    expect(within(findings).getByText("abcdef1234...567890")).toBeInTheDocument();
    expect(within(findings).queryByText("RAW-TOKEN-VALUE")).not.toBeInTheDocument();
  });
});

function seedCertificateMocks() {
  apiMock.certificatePage.mockResolvedValue({
    items: [
      {
        id: "cert-pay",
        tenant_id: "t1",
        owner_id: "team-platform",
        subject: "CN=payments.example.test",
        issuer: "CN=Platform CA",
        fingerprint: "sha256:pay",
        status: "active",
        profile_name: "prod-web",
        environment: "prod",
        deployment_location: "prod/payments",
      },
    ],
  });
  apiMock.owners.mockResolvedValue([{ id: "team-platform", tenant_id: "t1", kind: "team", name: "Platform Team" }]);
  apiMock.certificateHealth.mockResolvedValue(undefined);
  apiMock.crlDistributions.mockResolvedValue({ items: [] });
  apiMock.risk.mockResolvedValue([]);
  apiMock.rotationRuns.mockResolvedValue({ items: [] });
  apiMock.connectorDeliveries.mockResolvedValue({ items: [] });
}

function seedDiscoveryMocks() {
  apiMock.discoverySources.mockResolvedValue({
    items: [
      {
        id: "source-1",
        tenant_id: "tenant-1",
        kind: "network",
        name: "edge",
        config: { targets: ["10.0.0.10:443"] },
        created_at: "2026-06-20T10:00:00Z",
        updated_at: "2026-06-20T10:00:00Z",
      },
    ],
  });
  apiMock.discoverySchedules.mockResolvedValue({
    items: [
      {
        id: "schedule-1",
        tenant_id: "tenant-1",
        source_id: "source-1",
        name: "edge-hourly",
        interval_seconds: 3600,
        enabled: true,
        created_at: "2026-06-20T10:01:00Z",
        updated_at: "2026-06-20T10:01:00Z",
      },
    ],
  });
  apiMock.discoveryRuns.mockResolvedValue({
    items: [
      {
        id: "run-1",
        tenant_id: "tenant-1",
        source_id: "source-1",
        status: "succeeded",
        dry_run: false,
        requested_by: "operator",
        targets: 1,
        discovered: 1,
        failed: 0,
        rejected: 0,
        created_at: "2026-06-20T10:02:00Z",
        completed_at: "2026-06-20T10:02:05Z",
      },
    ],
  });
  apiMock.discoveryMonitoring.mockResolvedValue({
    repository_path: "/api/v1/certificates",
    findings_path: "/api/v1/discovery/findings",
    sources_path: "/api/v1/discovery/sources",
    schedules_path: "/api/v1/discovery/schedules",
    runs_path: "/api/v1/discovery/runs",
    summary: {
      source_count: 1,
      scheduled_source_count: 1,
      active_monitoring_count: 1,
      run_count: 1,
      completed_run_count: 1,
      failed_run_count: 0,
      finding_count: 1,
      open_finding_count: 1,
      certificate_inventory_count: 1,
    },
    sources: [
      {
        source_id: "source-1",
        kind: "network",
        name: "edge",
        scheduled: true,
        schedule_id: "schedule-1",
        monitoring_interval_seconds: 3600,
        last_run_id: "run-1",
        last_run_status: "succeeded",
        last_run_error: "",
        last_run_completed_at: "2026-06-20T10:02:05Z",
        last_discovery_at: "2026-06-20T10:02:04Z",
        run_count: 1,
        completed_run_count: 1,
        failed_run_count: 0,
        finding_count: 1,
        open_finding_count: 1,
        certificate_inventory_count: 1,
        repository_path: "/api/v1/certificates",
        findings_path: "/api/v1/discovery/findings?run_id=run-1",
        updated_at: "2026-06-20T10:00:00Z",
      },
    ],
  });
  apiMock.nhiShadowPosture.mockResolvedValue(undefined);
  apiMock.discoveryFindings.mockResolvedValue({
    items: [
      {
        id: "finding-1",
        tenant_id: "tenant-1",
        run_id: "run-1",
        source_id: "source-1",
        kind: "x509_certificate",
        ref: "10.0.0.10:443",
        provenance: "network:10.0.0.10:443",
        fingerprint: "abcdef1234567890abcdef1234567890",
        risk_score: 10,
        metadata: { owner: "platform", team: "certops", tags: ["internet", "tls"], secret_value: "RAW-TOKEN-VALUE" },
        discovered_at: "2026-06-20T10:02:04Z",
        triage_status: "unmanaged",
      },
    ],
  });
  apiMock.createDiscoverySource.mockResolvedValue({});
  apiMock.createDiscoverySchedule.mockResolvedValue({});
  apiMock.startDiscoveryRun.mockResolvedValue({});
}
