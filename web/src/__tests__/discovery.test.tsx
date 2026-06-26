import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { ApiError } from "@/lib/api";
import { Discovery } from "@/pages/Discovery";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    discoverySources: vi.fn(),
    discoverySchedules: vi.fn(),
    discoveryRuns: vi.fn(),
    discoveryFindings: vi.fn(),
    createDiscoverySource: vi.fn(),
    createDiscoverySchedule: vi.fn(),
    startDiscoveryRun: vi.fn(),
  },
}));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: apiMock };
});

function renderDiscovery() {
  return render(
    <MemoryRouter>
      <Discovery />
    </MemoryRouter>,
  );
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
        metadata: { secret_value: "RAW-TOKEN-VALUE" },
        discovered_at: "2026-06-20T10:02:04Z",
      },
    ],
  });
  apiMock.createDiscoverySource.mockResolvedValue({
    id: "source-2",
    tenant_id: "tenant-1",
    kind: "network",
    name: "edge-2",
    config: { targets: ["10.0.0.11:443"] },
    created_at: "2026-06-20T11:00:00Z",
    updated_at: "2026-06-20T11:00:00Z",
  });
  apiMock.createDiscoverySchedule.mockResolvedValue({
    id: "schedule-2",
    tenant_id: "tenant-1",
    source_id: "source-1",
    name: "daily",
    interval_seconds: 86400,
    enabled: true,
  });
  apiMock.startDiscoveryRun.mockResolvedValue({
    id: "run-2",
    tenant_id: "tenant-1",
    source_id: "source-1",
    status: "queued",
    dry_run: false,
    targets: 0,
    discovered: 0,
    failed: 0,
    rejected: 0,
    created_at: "2026-06-20T11:05:00Z",
  });
}

describe("discovery control-plane surface", () => {
  beforeEach(() => {
    localStorage.clear();
    sessionStorage.clear();
    vi.restoreAllMocks();
    for (const fn of Object.values(apiMock)) fn.mockReset();
    seedDiscoveryMocks();
  });

  it("renders served sources, schedules, runs, and findings without the old blocked disclosure", async () => {
    const storageSpy = vi.spyOn(Storage.prototype, "setItem");
    renderDiscovery();

    expect(await screen.findByRole("heading", { name: "Discovery" })).toBeInTheDocument();
    expect(screen.queryByText("Discovery scan API not served yet")).not.toBeInTheDocument();
    expect((await screen.findAllByText("edge")).length).toBeGreaterThanOrEqual(1);
    expect(await screen.findByText("edge-hourly")).toBeInTheDocument();
    expect(screen.getByText("run-1")).toBeInTheDocument();
    expect(screen.getByText("x509_certificate")).toBeInTheDocument();
    expect(screen.getByText("abcdef1234...567890")).toBeInTheDocument();
    expect(screen.queryByText("RAW-TOKEN-VALUE")).not.toBeInTheDocument();
    expect(storageSpy).not.toHaveBeenCalled();
    expect(localStorage.length).toBe(0);
    expect(sessionStorage.length).toBe(0);
  });

  it("creates a network source with host:port targets and can queue a run", async () => {
    const user = userEvent.setup();
    renderDiscovery();

    await screen.findByRole("heading", { name: "Source" });
    const sourceForm = screen.getByRole("heading", { name: "Source" }).closest("form");
    expect(sourceForm).toBeTruthy();
    await user.type(within(sourceForm as HTMLFormElement).getByLabelText("Name"), "edge-2");
    await user.type(within(sourceForm as HTMLFormElement).getByLabelText("Targets"), "10.0.0.11:443\n10.0.0.12:8443");
    await user.click(within(sourceForm as HTMLFormElement).getByRole("button", { name: "Create source" }));

    expect(apiMock.createDiscoverySource).toHaveBeenCalledWith({
      name: "edge-2",
      kind: "network",
      config: { targets: ["10.0.0.11:443", "10.0.0.12:8443"] },
    });

    await user.click(screen.getAllByRole("button", { name: "Run" })[0]);
    expect(apiMock.startDiscoveryRun).toHaveBeenCalledWith({ source_id: "source-1", dry_run: false });
  });

  it("uses permission and empty states when discovery records are unavailable or absent", async () => {
    apiMock.discoverySources.mockRejectedValueOnce(new ApiError(403, JSON.stringify({ detail: "missing discovery:read" })));
    apiMock.discoverySchedules.mockResolvedValueOnce({ items: [] });
    apiMock.discoveryRuns.mockResolvedValueOnce({ items: [] });
    apiMock.discoveryFindings.mockResolvedValueOnce({ items: [] });
    renderDiscovery();

    expect(await screen.findByText("Permission denied")).toBeInTheDocument();
    expect(screen.getByText("missing discovery:read")).toBeInTheDocument();
    expect(screen.getByText("No discovery schedules")).toBeInTheDocument();
    expect(screen.getByText("No discovery runs")).toBeInTheDocument();
    expect(screen.getByText("No discovery findings")).toBeInTheDocument();
  });
});
