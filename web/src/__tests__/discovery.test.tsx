import { beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, useLocation } from "react-router-dom";
import { ApiError, type DiscoveryCapability } from "@/lib/api";
import { AppQueryProvider } from "@/lib/query";
import { Discovery } from "@/pages/Discovery";
import { sourceWizardFieldPaths, type PrimaryKind } from "@/pages/discovery/SourceSetup";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    discoverySources: vi.fn(),
    discoverySchedules: vi.fn(),
    discoveryRuns: vi.fn(),
    discoveryMonitoring: vi.fn(),
    discoveryCoverage: vi.fn(),
    nhiShadowPosture: vi.fn(),
    discoveryFindings: vi.fn(),
    discoveryCapabilities: vi.fn(),
    previewDiscoveryPlan: vi.fn(),
    claimDiscoveryFinding: vi.fn(),
    dismissDiscoveryFinding: vi.fn(),
    createDiscoverySource: vi.fn(),
    createDiscoverySchedule: vi.fn(),
    startDiscoveryRun: vi.fn(),
    ctMonitoring: vi.fn(),
    updateCTMonitoring: vi.fn(),
    getDiscoveryRun: vi.fn(),
  },
}));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: apiMock };
});

function LocationProbe() {
  const location = useLocation();
  return <div aria-label="location search">{location.search}</div>;
}

function renderDiscovery(initialEntries = ["/discovery"]) {
  return render(
    <AppQueryProvider>
      <MemoryRouter initialEntries={initialEntries}>
        <Discovery />
        <LocationProbe />
      </MemoryRouter>
    </AppQueryProvider>,
  );
}

function wizardCapability(kind: PrimaryKind, providers?: DiscoveryCapability["providers"]): DiscoveryCapability {
  return {
    kind,
    label: kind,
    purpose: `Purpose for ${kind}.`,
    data_handling: `Data handling for ${kind}.`,
    tool: "Discover",
    route: `/discovery?tab=sources&kind=${kind}`,
    setup_surface: "source_wizard",
    permission: "discovery:write",
    edition: "core",
    execution: kind === "network" || kind === "ssh" || kind === "adcs" ? "network-role relay" : "control plane",
    configuration: sourceWizardFieldPaths[kind].map((path) => ({
      path,
      label: path,
      type: path.endsWith("_ref") ? "credential_ref" : "string",
      required: path === "segment" || path === "providers[].provider",
      description: `Configuration for ${path}.`,
    })),
    providers,
    lifecycle: ["available", "queued", "running", "succeeded", "failed", "blocked"],
    console_stages: ["configure", "preview", "execute", "observe", "recover", "prove"],
    documentation_ref: "docs/features/discovery-and-inventory.md",
  };
}

function seedDiscoveryMocks() {
  apiMock.discoveryCapabilities.mockResolvedValue({
    schema_version: 1,
    items: [
      wizardCapability("network"),
      wizardCapability("ssh"),
      wizardCapability("adcs"),
      wizardCapability("cloud_certificate", [
        {
          id: "aws-acm",
          label: "AWS Certificate Manager",
          least_privilege: "List certificates",
          preferred_credential: "env: references",
          fields: [],
        },
      ]),
      wizardCapability("cloud_secret", [
        {
          id: "aws-secrets-manager",
          label: "AWS Secrets Manager",
          least_privilege: "List secret metadata",
          preferred_credential: "env: references",
          fields: [],
        },
      ]),
      wizardCapability("secret_store", [
        {
          id: "hashicorp-vault",
          label: "HashiCorp Vault",
          least_privilege: "List metadata",
          preferred_credential: "token_ref",
          fields: [],
        },
      ]),
    ],
  });
  apiMock.previewDiscoveryPlan.mockResolvedValue({
    kind: "network",
    execution: "network-role relay",
    protocol: "tls",
    connection_origin: "selected network-role relay",
    segment: "production-dmz",
    normalized_targets: ["10.0.0.11:443", "10.0.0.12:8443"],
    normalized_target_count: 2,
    preview_truncated: false,
    excluded_target_count: 0,
    child_job_count: 1,
    concurrency: 16,
    queue_depth: 256,
    estimated_upper_seconds: 10,
    permission: "discovery:write",
    data_handling: "Public metadata only.",
    side_effects: false,
    blocked_reasons: [],
  });
  apiMock.discoverySources.mockResolvedValue({
    items: [
      {
        id: "source-1",
        tenant_id: "tenant-1",
        kind: "network",
        name: "edge",
        config: { targets: ["10.0.0.10:443"], segment: "production-dmz", relay_agent_id: "relay-agent-1" },
        created_at: "2026-06-20T10:00:00Z",
        updated_at: "2026-06-20T10:00:00Z",
      },
      {
        id: "source-cloud-secrets",
        tenant_id: "tenant-1",
        kind: "cloud_secret",
        name: "cloud-secret-managers",
        config: {
          providers: [
            { provider: "aws-secrets-manager", region: "us-east-1", access_key_id_ref: "secret://aws/access-key" },
            { provider: "gcp-secret-manager", project: "payments-prod", token_ref: "secret://gcp/token" },
            { provider: "hashicorp-vault", vault_url: "https://vault.example", token_ref: "secret://vault/token", mount: "secret", path_prefix: "tls" },
          ],
        },
        created_at: "2026-06-20T10:00:30Z",
        updated_at: "2026-06-20T10:00:30Z",
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
        execution: "relay",
        segment: "production-dmz",
        required_agent_role: "network",
        required_agent_id: "relay-agent-1",
        executed_by_agent_id: "relay-agent-1",
        targets: 1,
        discovered: 1,
        failed: 0,
        rejected: 0,
        blocked: 0,
        created_at: "2026-06-20T10:02:00Z",
        completed_at: "2026-06-20T10:02:05Z",
      },
      {
        id: "run-cloud-secrets",
        tenant_id: "tenant-1",
        source_id: "source-cloud-secrets",
        status: "succeeded",
        dry_run: false,
        requested_by: "operator",
        execution: "control_plane",
        targets: 3,
        discovered: 3,
        failed: 0,
        rejected: 0,
        blocked: 0,
        created_at: "2026-06-20T10:03:00Z",
        completed_at: "2026-06-20T10:03:05Z",
      },
    ],
  });
  apiMock.ctMonitoring.mockResolvedValue({
    capability: "ct_log",
    findings_path: "/api/v1/discovery/findings",
    runs_path: "/api/v1/discovery/runs",
    sources_path: "/api/v1/discovery/sources",
    watchlist_path: "/api/v1/discovery/ct-monitoring",
    notification_destination: "notification.ct",
    outbox_backed_alerts: true,
    watched_domains: [],
    logs: [],
    retired_logs: [],
    findings: [],
    summary: {},
  });
  apiMock.updateCTMonitoring.mockResolvedValue({});
  apiMock.getDiscoveryRun.mockResolvedValue({ id: "run-ct", status: "succeeded" });
  apiMock.discoveryCoverage.mockResolvedValue({
    generated_at: "2026-06-20T10:05:00Z",
    observed: 1,
    unobserved: 1,
    structurally_unobservable: 1,
    classes: [
      { class: "tls-endpoint", status: "OBSERVED", source_kinds: ["network"], observed_by: ["edge-net"], last_observed_at: "2026-06-20T10:03:05Z" },
      {
        class: "ct-exposed-certificate",
        status: "OBSERVABLE-UNOBSERVED",
        source_kinds: ["ct_log"],
        reason: "no configured source observes this class",
        action: "configure a discovery source of kind ct_log (needs: monitored-domains-configured)",
      },
      { class: "firmware-embedded-crypto", status: "STRUCTURALLY-UNOBSERVABLE", reason: "no source inspects device firmware" },
    ],
  });
  apiMock.discoveryMonitoring.mockResolvedValue({
    repository_path: "/api/v1/certificates",
    findings_path: "/api/v1/discovery/findings",
    sources_path: "/api/v1/discovery/sources",
    schedules_path: "/api/v1/discovery/schedules",
    runs_path: "/api/v1/discovery/runs",
    summary: {
      source_count: 2,
      scheduled_source_count: 1,
      active_monitoring_count: 1,
      run_count: 2,
      completed_run_count: 2,
      failed_run_count: 0,
      finding_count: 3,
      open_finding_count: 3,
      certificate_inventory_count: 4,
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
        finding_count: 2,
        open_finding_count: 2,
        certificate_inventory_count: 1,
        repository_path: "/api/v1/certificates",
        findings_path: "/api/v1/discovery/findings?run_id=run-1",
        updated_at: "2026-06-20T10:00:00Z",
      },
      {
        source_id: "source-cloud-secrets",
        kind: "cloud_secret",
        name: "cloud-secret-managers",
        scheduled: false,
        schedule_id: "",
        monitoring_interval_seconds: 0,
        last_run_id: "run-cloud-secrets",
        last_run_status: "succeeded",
        last_run_error: "",
        last_run_completed_at: "2026-06-20T10:03:05Z",
        last_discovery_at: "2026-06-20T10:03:04Z",
        run_count: 1,
        completed_run_count: 1,
        failed_run_count: 0,
        finding_count: 3,
        open_finding_count: 3,
        certificate_inventory_count: 3,
        repository_path: "/api/v1/certificates",
        findings_path: "/api/v1/discovery/findings?run_id=run-cloud-secrets",
        updated_at: "2026-06-20T10:00:30Z",
      },
    ],
  });
  apiMock.nhiShadowPosture.mockResolvedValue({
    capability: "CAP-NHI-05",
    generated_at: "2026-06-20T10:04:00Z",
    coverage: ["discovery_findings", "unmanaged_triage", "unregistered_detection", "ownerless_detection"],
    summary: {
      total_analyzed: 3,
      findings: 2,
      unmanaged: 2,
      investigating: 0,
      unregistered: 2,
      ownerless: 1,
      critical: 0,
      high: 1,
      medium: 1,
      low: 0,
      kind_counts: { api_key: 1, certificate: 1 },
      surface_counts: { ci: 1, cloud: 1 },
    },
    findings: [
      {
        finding_id: "finding-2",
        source_id: "source-1",
        run_id: "run-1",
        kind: "api_key",
        ref: "github:user/payments-ci/pat",
        display_name: "payments-ci",
        surface: "ci",
        system: "github",
        provenance: "github:audit/pat-1",
        fingerprint: "1234567890abcdef1234567890abcdef",
        triage_status: "unmanaged",
        owner_status: "ownerless",
        severity: "high",
        risk_score: 80,
        recommendation: "Claim the finding to an existing identity or create one before allowing continued use.",
        evidence_refs: ["discovery.finding:finding-2", "metadata:surface"],
        discovered_at: "2026-06-20T10:02:06Z",
      },
    ],
    recommended_actions: ["Claim legitimate findings to managed identities."],
    evidence_refs: ["projection:discovery_findings"],
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
        metadata: { owner: "platform", team: "certops", tags: ["internet", "tls"], secret_value: "RAW-TOKEN-VALUE" },
        discovered_at: "2026-06-20T10:02:04Z",
        triage_status: "unmanaged",
      },
      {
        id: "finding-2",
        tenant_id: "tenant-1",
        run_id: "run-1",
        source_id: "source-1",
        kind: "api_key",
        ref: "github:user/payments-ci/pat",
        provenance: "github:audit/pat-1",
        fingerprint: "1234567890abcdef1234567890abcdef",
        risk_score: 80,
        metadata: { owner: "payments", team: "payments", tags: ["orphaned"] },
        discovered_at: "2026-06-20T10:02:06Z",
        triage_status: "unmanaged",
      },
      {
        id: "finding-cloud-secret-vault",
        tenant_id: "tenant-1",
        run_id: "run-cloud-secrets",
        source_id: "source-cloud-secrets",
        kind: "x509_certificate",
        ref: "vault://vault.example/secret/tls/web",
        provenance: "vault://vault.example/secret/tls/web",
        fingerprint: "fedcba9876543210fedcba9876543210",
        risk_score: 20,
        metadata: { provider: "hashicorp-vault", secret_name: "tls/web", secret_value: "VAULT-RAW-SECRET", owner: "platform", tags: ["cloud-secret"] },
        discovered_at: "2026-06-20T10:03:04Z",
        triage_status: "unmanaged",
      },
    ],
  });
  apiMock.createDiscoverySource.mockResolvedValue({
    id: "source-2",
    tenant_id: "tenant-1",
    kind: "network",
    name: "edge-2",
    config: { targets: ["10.0.0.11:443"], segment: "production-dmz" },
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
    execution: "relay",
    segment: "production-dmz",
    targets: 0,
    discovered: 0,
    failed: 0,
    rejected: 0,
    blocked: 0,
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

  it("implements the quiet Discover contract while retaining exact evidence", async () => {
    const user = userEvent.setup();
    renderDiscovery();

    expect(await screen.findByRole("heading", { level: 1, name: "Discover" })).toBeInTheDocument();
    expect(screen.getByText("What was found, why it matters, and the next valid action.")).toBeInTheDocument();
    expect(screen.getByText("What needs attention")).toBeInTheDocument();

    const runScan = screen.getByRole("button", { name: "Run scan" });
    expect(runScan).toBeInTheDocument();
    const exactMonitoring = screen.getByText("Monitoring and exact scan evidence").closest("details");
    expect(exactMonitoring).toBeTruthy();
    expect(exactMonitoring).not.toHaveAttribute("open");

    const findingsSection = screen.getByRole("heading", { name: "Credentials to review" }).closest("section");
    expect(findingsSection).toBeTruthy();
    expect(Boolean((findingsSection as HTMLElement).compareDocumentPosition(exactMonitoring as HTMLElement) & Node.DOCUMENT_POSITION_FOLLOWING)).toBe(true);
    const findingsTable = within(findingsSection as HTMLElement).getByRole("table", { name: "Discovery findings" });
    expect(within(findingsTable).getAllByRole("columnheader")).toHaveLength(5);
    expect(within(findingsTable).queryByRole("columnheader", { name: "Status" })).not.toBeInTheDocument();
    expect(within(findingsTable).queryByRole("columnheader", { name: "Credential type" })).not.toBeInTheDocument();
    expect(within(findingsTable).queryByRole("columnheader", { name: "Discovered" })).not.toBeInTheDocument();

    const certRow = screen.getByText("10.0.0.10:443").closest("tr");
    expect(certRow).toBeTruthy();
    expect(within(certRow as HTMLTableRowElement).getByText("TLS certificate")).toBeInTheDocument();
    expect(within(certRow as HTMLTableRowElement).queryByText("x509_certificate")).not.toBeInTheDocument();
    expect(within(certRow as HTMLTableRowElement).getByRole("button", { name: "Review finding" })).toBeInTheDocument();
    expect(within(certRow as HTMLTableRowElement).queryByRole("button", { name: "Claim" })).not.toBeInTheDocument();

    await user.click(within(certRow as HTMLTableRowElement).getByRole("button", { name: "Review finding" }));
    const detail = screen.getByRole("heading", { name: "Finding detail" }).closest("aside");
    expect(detail).toBeTruthy();
    expect(within(detail as HTMLElement).getByRole("button", { name: "Claim" })).toBeInTheDocument();
    const exactFinding = within(detail as HTMLElement)
      .getByText("Exact finding evidence")
      .closest("details");
    expect(exactFinding).toBeTruthy();
    expect(exactFinding).not.toHaveAttribute("open");
    await user.click(within(exactFinding as HTMLElement).getByText("Exact finding evidence"));
    expect(exactFinding).toHaveAttribute("open");
    expect(within(exactFinding as HTMLElement).getByText("finding-1")).toBeInTheDocument();
    expect(within(exactFinding as HTMLElement).getByText("x509_certificate")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Run scan" }));
    expect(screen.getByRole("tab", { name: "Sources" })).toHaveAttribute("aria-selected", "true");
    expect((await screen.findAllByRole("button", { name: "Run" }))[0]).toHaveFocus();
  });

  it("keeps an unavailable source ID in exact evidence instead of leaking it into the default decision path", async () => {
    const seededSources = await apiMock.discoverySources();
    apiMock.discoverySources.mockResolvedValue({
      items: seededSources.items.filter((source: { id: string }) => source.id !== "source-cloud-secrets"),
    });
    const user = userEvent.setup();
    renderDiscovery();

    const findingRow = (await screen.findByText("vault://vault.example/secret/tls/web")).closest("tr");
    expect(findingRow).toBeTruthy();
    expect(within(findingRow as HTMLTableRowElement).getByText("Unknown source")).toBeInTheDocument();
    expect(within(findingRow as HTMLTableRowElement).queryByText("source-cloud-secrets")).not.toBeInTheDocument();

    await user.click(within(findingRow as HTMLTableRowElement).getByRole("button", { name: "Review finding" }));
    const detail = screen.getByRole("heading", { name: "Finding detail" }).closest("aside");
    expect(detail).toBeTruthy();
    expect(within(detail as HTMLElement).getByText("Unknown source")).toBeInTheDocument();
    const exactFinding = within(detail as HTMLElement)
      .getByText("Exact finding evidence")
      .closest("details") as HTMLDetailsElement;
    await user.click(within(exactFinding).getByText("Exact finding evidence"));
    expect(within(exactFinding).getByText("source-cloud-secrets")).toBeInTheDocument();
  });

  it("renders served sources, schedules, runs, and findings without the old blocked disclosure", async () => {
    const storageSpy = vi.spyOn(Storage.prototype, "setItem");
    const user = userEvent.setup();
    renderDiscovery();

    expect(await screen.findByRole("heading", { name: "Discover" })).toBeInTheDocument();
    expect(screen.queryByText("Discovery scan API not served yet")).not.toBeInTheDocument();

    // Findings are the default reading path; exact monitoring/shadow posture is
    // still reachable through one deliberate evidence disclosure.
    await user.click(screen.getByText("Monitoring and exact scan evidence"));
    const monitoring = screen.getByRole("heading", { name: "Continuous monitoring" }).closest("section");
    expect(monitoring).toBeTruthy();
    expect(within(monitoring as HTMLElement).getByText("Scheduled")).toBeInTheDocument();
    expect(within(monitoring as HTMLElement).getByText("1h")).toBeInTheDocument();
    expect(within(monitoring as HTMLElement).getAllByText("/api/v1/certificates").length).toBeGreaterThanOrEqual(1);
    expect(within(monitoring as HTMLElement).getByText("/api/v1/discovery/findings?run_id=run-1")).toBeInTheDocument();
    const shadow = screen.getByRole("heading", { name: "Shadow NHI posture" }).closest("section");
    expect(shadow).toBeTruthy();
    expect(within(shadow as HTMLElement).getByText("CAP-NHI-05")).toBeInTheDocument();
    expect(within(shadow as HTMLElement).getByText("Unregistered")).toBeInTheDocument();
    expect(within(shadow as HTMLElement).getByText("github:user/payments-ci/pat")).toBeInTheDocument();
    expect(screen.queryByText("RAW-TOKEN-VALUE")).not.toBeInTheDocument();
    expect(screen.queryByText("VAULT-RAW-SECRET")).not.toBeInTheDocument();

    const certRow = screen.getByText("10.0.0.10:443").closest("tr") as HTMLTableRowElement;
    await user.click(within(certRow).getByRole("button", { name: "Review finding" }));
    const exactFinding = screen.getByText("Exact finding evidence").closest("details") as HTMLDetailsElement;
    await user.click(within(exactFinding).getByText("Exact finding evidence"));
    expect(within(exactFinding).getByText("abcdef1234567890abcdef1234567890")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Close" }));

    await user.click(screen.getByRole("tab", { name: "Sources" }));
    expect((await screen.findAllByText("edge")).length).toBeGreaterThanOrEqual(1);
    expect((await screen.findAllByText("cloud-secret-managers")).length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText("Cloud secrets").length).toBeGreaterThanOrEqual(1);

    await user.click(screen.getByRole("tab", { name: "Schedules" }));
    expect(await screen.findByText("edge-hourly")).toBeInTheDocument();

    await user.click(screen.getByRole("tab", { name: "Runs" }));
    expect(screen.getByText("run-1")).toBeInTheDocument();

    expect(storageSpy).not.toHaveBeenCalled();
    expect(localStorage.length).toBe(0);
    expect(sessionStorage.length).toBe(0);
  });

  it("claims and dismisses findings while keeping owner and tag filters URL-addressable", async () => {
    const user = userEvent.setup();
    const initialPosture = await apiMock.nhiShadowPosture();
    apiMock.nhiShadowPosture.mockReset();
    apiMock.nhiShadowPosture.mockResolvedValueOnce(initialPosture).mockResolvedValue({
      ...initialPosture,
      generated_at: "2026-06-20T10:04:01Z",
      summary: { ...initialPosture.summary, unmanaged: 1, findings: 1 },
    });
    apiMock.claimDiscoveryFinding.mockResolvedValue({
      id: "finding-1",
      tenant_id: "tenant-1",
      run_id: "run-1",
      source_id: "source-1",
      kind: "x509_certificate",
      ref: "10.0.0.10:443",
      provenance: "network:10.0.0.10:443",
      fingerprint: "abcdef1234567890abcdef1234567890",
      risk_score: 10,
      metadata: { owner: "platform", team: "certops", tags: ["internet", "tls", "follow-up"] },
      discovered_at: "2026-06-20T10:02:04Z",
      triage_status: "managed",
      managed_identity_id: "identity-1",
      triage_reason: "matched managed certificate",
      triage_actor: "operator",
      triaged_at: "2026-06-20T10:04:00Z",
    });
    apiMock.dismissDiscoveryFinding.mockResolvedValue({
      id: "finding-2",
      tenant_id: "tenant-1",
      run_id: "run-1",
      source_id: "source-1",
      kind: "api_key",
      ref: "github:user/payments-ci/pat",
      provenance: "github:audit/pat-1",
      fingerprint: "1234567890abcdef1234567890abcdef",
      risk_score: 80,
      metadata: { owner: "payments", team: "payments", tags: ["orphaned"] },
      discovered_at: "2026-06-20T10:02:06Z",
      triage_status: "dismissed",
      triage_reason: "duplicate scanner evidence",
      triage_actor: "operator",
      triaged_at: "2026-06-20T10:05:00Z",
    });

    renderDiscovery();

    const attention = (await screen.findByText("What needs attention")).closest("section");
    expect(attention).toBeTruthy();
    expect(
      within(
        within(attention as HTMLElement)
          .getByText("Unmanaged")
          .closest(".rounded-panel") as HTMLElement,
      ).getByText("3"),
    ).toBeInTheDocument();

    const certRow = (await screen.findByText("10.0.0.10:443")).closest("tr");
    expect(certRow).toBeTruthy();
    expect(within(certRow as HTMLTableRowElement).getByText("platform")).toBeInTheDocument();

    await user.click(within(certRow as HTMLTableRowElement).getByRole("button", { name: "Review finding" }));
    const claimPanel = screen.getByRole("heading", { name: "Finding detail" }).closest("aside");
    expect(claimPanel).toBeTruthy();
    expect(within(claimPanel as HTMLElement).getByText("certops")).toBeInTheDocument();
    expect(within(claimPanel as HTMLElement).getByText("internet")).toBeInTheDocument();
    await user.click(within(claimPanel as HTMLElement).getByRole("button", { name: "Claim" }));
    await user.type(screen.getByLabelText("Managed identity"), "identity-1");
    await user.type(screen.getByLabelText("Reason"), "matched managed certificate");
    await user.clear(within(claimPanel as HTMLElement).getByLabelText("Tags"));
    await user.type(within(claimPanel as HTMLElement).getByLabelText("Tags"), "internet, tls, follow-up");
    await user.click(screen.getByRole("button", { name: "Claim as managed" }));

    expect(apiMock.claimDiscoveryFinding).toHaveBeenCalledWith("finding-1", {
      managed_identity_id: "identity-1",
      reason: "matched managed certificate",
      owner: "platform",
      team: "certops",
      tags: ["internet", "tls", "follow-up"],
    });
    expect(await within(certRow as HTMLTableRowElement).findByText("Managed")).toBeInTheDocument();
    expect(
      within(
        within(attention as HTMLElement)
          .getByText("Unmanaged")
          .closest(".rounded-panel") as HTMLElement,
      ).getByText("2"),
    ).toBeInTheDocument();
    expect(apiMock.nhiShadowPosture).toHaveBeenCalledTimes(2);
    await user.click(screen.getByText("Monitoring and exact scan evidence"));
    const shadow = screen.getByRole("heading", { name: "Shadow NHI posture" }).closest("section");
    expect(shadow).toBeTruthy();
    expect(
      within(
        within(shadow as HTMLElement)
          .getByText("Unmanaged")
          .closest(".ui-panel") as HTMLElement,
      ).getByText("1"),
    ).toBeInTheDocument();
    expect(await within(claimPanel as HTMLElement).findByText("follow-up")).toBeInTheDocument();
    await user.click(within(claimPanel as HTMLElement).getByRole("button", { name: "Close" }));

    const tokenRow = screen
      .getAllByText("github:user/payments-ci/pat")
      .map((node) => node.closest("tr"))
      .find((row) => row && within(row as HTMLTableRowElement).queryByRole("button", { name: "Review finding" }));
    expect(tokenRow).toBeTruthy();
    await user.click(within(tokenRow as HTMLTableRowElement).getByRole("button", { name: "Review finding" }));
    const tokenPanel = screen.getByRole("heading", { name: "Finding detail" }).closest("aside") as HTMLElement;
    await user.click(within(tokenPanel).getByText("More actions"));
    await user.click(within(tokenPanel).getByRole("button", { name: "Dismiss" }));
    await user.clear(screen.getByLabelText("Reason"));
    await user.type(screen.getByLabelText("Reason"), "duplicate scanner evidence");
    await user.click(screen.getByRole("button", { name: "Dismiss finding" }));

    expect(apiMock.dismissDiscoveryFinding).toHaveBeenCalledWith("finding-2", {
      reason: "duplicate scanner evidence",
      owner: "payments",
      team: "payments",
      tags: ["orphaned"],
    });
    expect(await within(tokenRow as HTMLTableRowElement).findByText("Dismissed")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Close" }));

    const findingsSection = screen.getByRole("heading", { name: "Credentials to review" }).closest("section");
    expect(findingsSection).toBeTruthy();
    await user.click(within(findingsSection as HTMLElement).getByRole("button", { name: "Filters" }));
    await user.selectOptions(screen.getByLabelText("Owner"), "platform");
    await user.selectOptions(screen.getByLabelText("Team"), "certops");
    await user.selectOptions(screen.getByLabelText("Tag"), "follow-up");
    await user.selectOptions(screen.getByLabelText("Triage status"), "managed");

    const params = new URLSearchParams(screen.getByLabelText("location search").textContent ?? "");
    expect(params.get("owner")).toBe("platform");
    expect(params.get("team")).toBe("certops");
    expect(params.get("tag")).toBe("follow-up");
    expect(params.get("triage")).toBe("managed");
    expect(screen.getByText("10.0.0.10:443")).toBeInTheDocument();
    expect(within(findingsSection as HTMLElement).queryByText("github:user/payments-ci/pat")).not.toBeInTheDocument();
  });

  it("creates a network source with host:port targets and can queue a run", async () => {
    const user = userEvent.setup();
    renderDiscovery(["/discovery?tab=sources"]);

    const sourceForm = await screen.findByRole("form", { name: "Set up a discovery source" });
    expect(screen.getByRole("columnheader", { name: "Execution binding" })).toBeInTheDocument();
    expect(screen.getByText(/Relay · production-dmz/)).toBeInTheDocument();
    await user.type(within(sourceForm).getByLabelText("Source name"), "edge-2");
    await user.type(within(sourceForm).getByLabelText("Authorized scope"), "production-dmz");
    await user.type(within(sourceForm).getByLabelText("Network relay"), "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa");
    await user.type(within(sourceForm).getByLabelText(/Hosts, IPs/), "10.0.0.11:443\n10.0.0.12:8443");
    await user.click(within(sourceForm).getByRole("button", { name: "Review exact plan" }));
    await user.click(await within(sourceForm).findByRole("button", { name: "Save source" }));

    expect(apiMock.createDiscoverySource).toHaveBeenCalledWith({
      name: "edge-2",
      kind: "network",
      config: {
        targets: ["10.0.0.11:443", "10.0.0.12:8443"],
        ports: [443, 8443],
        segment: "production-dmz",
        relay_agent_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
      },
    });

    await user.click(screen.getAllByRole("button", { name: "Run" })[0]);
    expect(apiMock.startDiscoveryRun).toHaveBeenCalledWith({ source_id: "source-1", dry_run: false });
  });

  it("shows relay segment and executing-agent provenance in run history", async () => {
    renderDiscovery(["/discovery?tab=runs"]);
    expect(await screen.findByRole("columnheader", { name: "Executor" })).toBeInTheDocument();
    expect(screen.getByText(/Relay · production-dmz · relay-agent-/)).toBeInTheDocument();
    expect(screen.getByText("Control plane")).toBeInTheDocument();
  });

  it("uses structured templates instead of primary JSON textareas for complex source creation", async () => {
    const user = userEvent.setup();
    renderDiscovery(["/discovery?tab=sources"]);

    await screen.findByRole("heading", { name: "Import sanitized observations" });
    const sourceForm = screen.getByRole("heading", { name: "Import sanitized observations" }).closest("form");
    expect(sourceForm).toBeTruthy();

    const complexSources = [
      { kind: "nhi_cross_surface", oldJsonLabel: "Observations JSON" },
      { kind: "api_key", oldJsonLabel: "Observations JSON" },
      { kind: "oauth_grant", oldJsonLabel: "OAuth grants JSON" },
      { kind: "service_account", oldJsonLabel: "Service accounts JSON" },
      { kind: "nhi_behavior", oldJsonLabel: "Behavior events JSON" },
      { kind: "credential_compromise", oldJsonLabel: "Compromise signals JSON" },
      { kind: "k8s_ingress_gateway", oldJsonLabel: "Kubernetes resources JSON" },
    ];

    for (const source of complexSources) {
      await user.selectOptions(within(sourceForm as HTMLFormElement).getByLabelText("Kind"), source.kind);

      expect(within(sourceForm as HTMLFormElement).queryByLabelText(source.oldJsonLabel)).not.toBeInTheDocument();
      expect(within(sourceForm as HTMLFormElement).getByLabelText("Source template")).toBeInTheDocument();
      expect(within(sourceForm as HTMLFormElement).getByRole("button", { name: "Load sample" })).toBeInTheDocument();
      expect(within(sourceForm as HTMLFormElement).getByLabelText("CSV upload")).toBeInTheDocument();
      expect(within(sourceForm as HTMLFormElement).getByRole("button", { name: "Advanced JSON import" })).toBeInTheDocument();
    }
  });

  it("creates a cross-surface NHI source from metadata-only observations", async () => {
    const user = userEvent.setup();
    renderDiscovery(["/discovery?tab=sources"]);

    await screen.findByRole("heading", { name: "Import sanitized observations" });
    const sourceForm = screen.getByRole("heading", { name: "Import sanitized observations" }).closest("form");
    expect(sourceForm).toBeTruthy();
    await user.type(within(sourceForm as HTMLFormElement).getByLabelText("Name"), "nhi-quarterly");
    await user.selectOptions(within(sourceForm as HTMLFormElement).getByLabelText("Kind"), "nhi_cross_surface");
    await user.click(within(sourceForm as HTMLFormElement).getByRole("button", { name: "Advanced JSON import" }));
    fireEvent.change(within(sourceForm as HTMLFormElement).getByLabelText("NHI surfaces JSON import"), {
      target: {
        value: JSON.stringify([
          { surface: "idp", system: "okta", external_id: "app/payments", principal: "payments-api" },
          { surface: "cloud", system: "aws-iam", external_id: "role/payments-prod", principal: "payments-role" },
          { surface: "saas", system: "github", external_id: "app/installations/42", principal: "payments-ci-app" },
          { surface: "on_prem", system: "ldap", external_id: "svc-payments", principal: "svc-payments" },
          { surface: "code", system: "github-code-search", external_id: "repo/payments/path/deploy.yaml", principal: "payments-deploy-key" },
          { surface: "ci", system: "github-actions", external_id: "repo/payments/env/prod", principal: "payments-ci-token" },
        ]),
      },
    });
    await user.click(within(sourceForm as HTMLFormElement).getByRole("button", { name: "Create source" }));

    expect(apiMock.createDiscoverySource).toHaveBeenCalledWith({
      name: "nhi-quarterly",
      kind: "nhi_cross_surface",
      config: {
        observations: expect.arrayContaining([
          expect.objectContaining({ surface: "idp", system: "okta" }),
          expect.objectContaining({ surface: "ci", system: "github-actions" }),
        ]),
      },
    });
  });

  it("creates a reference-only AD CS source for a network relay", async () => {
    const user = userEvent.setup();
    renderDiscovery(["/discovery?tab=sources"]);

    const sourceForm = await screen.findByRole("form", { name: "Set up a discovery source" });
    const form = within(sourceForm);
    await user.type(form.getByLabelText("Source name"), "corp-adcs");
    await user.selectOptions(form.getByLabelText("What should trstctl inspect?"), "adcs");
    await user.clear(form.getByLabelText("Directory URL"));
    await user.type(form.getByLabelText("Directory URL"), "ldaps://dc01.corp.example:636");
    await user.type(form.getByLabelText("Configuration naming context"), "CN=Configuration,DC=corp,DC=example");
    await user.type(form.getByLabelText("Bind identity"), "CN=trstctl-reader,OU=Service Accounts,DC=corp,DC=example");
    await user.type(form.getByLabelText("Password reference"), "secret://adcs/domain-reader");
    await user.type(form.getByLabelText("Network relay"), "11111111-1111-4111-8111-111111111111");
    await user.click(form.getByText("Enrollment endpoint boundary"));
    await user.type(form.getByLabelText("Enrollment endpoints"), "Corporate web enrollment | web_enrollment | https://certs.corp.example/certsrv/");
    await user.click(form.getByRole("checkbox", { name: /Allow an approved private endpoint/ }));
    await user.type(form.getByLabelText("Approved private endpoint CIDRs"), "10.42.0.0/16");
    await user.click(form.getByRole("button", { name: "Review exact plan" }));
    await user.click(await form.findByRole("button", { name: "Save source" }));

    expect(apiMock.createDiscoverySource).toHaveBeenCalledWith({
      name: "corp-adcs",
      kind: "adcs",
      config: {
        url: "ldaps://dc01.corp.example:636",
        configuration_dn: "CN=Configuration,DC=corp,DC=example",
        bind_dn: "CN=trstctl-reader,OU=Service Accounts,DC=corp,DC=example",
        password_ref: "secret://adcs/domain-reader",
        relay_agent_id: "11111111-1111-4111-8111-111111111111",
        enrollment_endpoints: [
          {
            enrollment_service: "Corporate web enrollment",
            kind: "web_enrollment",
            url: "https://certs.corp.example/certsrv/",
          },
        ],
        allow_private_endpoint: true,
        private_egress_cidrs: ["10.42.0.0/16"],
      },
    });
  });

  it("creates an API-key and token source from metadata-only observations", async () => {
    const user = userEvent.setup();
    renderDiscovery(["/discovery?tab=sources"]);

    await screen.findByRole("heading", { name: "Import sanitized observations" });
    const sourceForm = screen.getByRole("heading", { name: "Import sanitized observations" }).closest("form");
    expect(sourceForm).toBeTruthy();
    await user.type(within(sourceForm as HTMLFormElement).getByLabelText("Name"), "tokens-quarterly");
    await user.selectOptions(within(sourceForm as HTMLFormElement).getByLabelText("Kind"), "api_key");
    await user.click(within(sourceForm as HTMLFormElement).getByRole("button", { name: "Advanced JSON import" }));
    fireEvent.change(within(sourceForm as HTMLFormElement).getByLabelText("API keys JSON import"), {
      target: {
        value: JSON.stringify([
          {
            surface: "saas",
            system: "github",
            external_id: "user/payments-ci/pat",
            principal: "payments-ci",
            credential_kind: "personal_access_token",
            credential_ref: "github:user/payments-ci/pat",
            masked_fingerprint: "sha256:github-pat-ref",
            evidence_refs: ["github:audit/pat-1"],
          },
          {
            surface: "cloud",
            system: "aws-iam",
            external_id: "access-key/AKIAEXAMPLE",
            principal: "arn:aws:iam::111111111111:user/payments-deploy",
            credential_kind: "access_key",
            credential_ref: "aws-iam:111111111111:access-key/AKIAEXAMPLE",
            masked_fingerprint: "sha256:aws-access-key-ref",
            evidence_refs: ["aws-iam:credential-report"],
          },
        ]),
      },
    });
    await user.click(within(sourceForm as HTMLFormElement).getByRole("button", { name: "Create source" }));

    expect(apiMock.createDiscoverySource).toHaveBeenCalledWith({
      name: "tokens-quarterly",
      kind: "api_key",
      config: {
        observations: expect.arrayContaining([
          expect.objectContaining({ system: "github", credential_kind: "personal_access_token" }),
          expect.objectContaining({ system: "aws-iam", credential_kind: "access_key" }),
        ]),
      },
    });
  });

  it("creates an OAuth grant source from metadata-only app consent records", async () => {
    const user = userEvent.setup();
    renderDiscovery(["/discovery?tab=sources"]);

    await screen.findByRole("heading", { name: "Import sanitized observations" });
    const sourceForm = screen.getByRole("heading", { name: "Import sanitized observations" }).closest("form");
    expect(sourceForm).toBeTruthy();
    await user.type(within(sourceForm as HTMLFormElement).getByLabelText("Name"), "oauth-quarterly");
    await user.selectOptions(within(sourceForm as HTMLFormElement).getByLabelText("Kind"), "oauth_grant");
    const csv = [
      "provider,app_id,app_name,principal,resource,scopes,consent_type,third_party,owner,publisher_verified,threat_signals,evidence_refs",
      'okta,0oa-payments,Payments BI Export,payments-bi-export,google-workspace,"drive.readonly, admin.directory.user.readonly",admin,true,finance-platform,false,consent_phishing,okta:audit/consent-42',
    ].join("\n");
    await user.upload(within(sourceForm as HTMLFormElement).getByLabelText("CSV upload"), new File([csv], "oauth-grants.csv", { type: "text/csv" }));
    await user.click(within(sourceForm as HTMLFormElement).getByRole("button", { name: "Create source" }));

    expect(apiMock.createDiscoverySource).toHaveBeenCalledWith({
      name: "oauth-quarterly",
      kind: "oauth_grant",
      config: {
        grants: [
          expect.objectContaining({
            provider: "okta",
            app_id: "0oa-payments",
            resource: "google-workspace",
            publisher_verified: false,
            threat_signals: ["consent_phishing"],
            evidence_refs: ["okta:audit/consent-42"],
          }),
        ],
      },
    });
  });

  it("creates a service-account source from AD and cloud inventory metadata", async () => {
    const user = userEvent.setup();
    renderDiscovery(["/discovery?tab=sources"]);

    await screen.findByRole("heading", { name: "Import sanitized observations" });
    const sourceForm = screen.getByRole("heading", { name: "Import sanitized observations" }).closest("form");
    expect(sourceForm).toBeTruthy();
    await user.type(within(sourceForm as HTMLFormElement).getByLabelText("Name"), "service-accounts");
    await user.selectOptions(within(sourceForm as HTMLFormElement).getByLabelText("Kind"), "service_account");
    await user.click(within(sourceForm as HTMLFormElement).getByRole("button", { name: "Advanced JSON import" }));
    fireEvent.change(within(sourceForm as HTMLFormElement).getByLabelText("Service accounts JSON import"), {
      target: {
        value: JSON.stringify([
          {
            surface: "active_directory",
            provider: "ad",
            directory: "corp.example",
            account_id: "S-1-5-21-1000",
            principal: "svc-payments@corp.example",
            owner: "identity",
            groups: ["CN=Payments,OU=Service Accounts,DC=corp,DC=example"],
            credential_refs: ["ad:corp.example:svc-payments"],
          },
          {
            surface: "cloud",
            provider: "aws-iam",
            directory: "111111111111",
            account_id: "role/payments-prod",
            principal: "arn:aws:iam::111111111111:role/payments-prod",
            owner: "platform",
            privileged: true,
            roles: ["AdministratorAccess"],
            credential_refs: ["aws:iam:role/payments-prod"],
          },
        ]),
      },
    });
    await user.click(within(sourceForm as HTMLFormElement).getByRole("button", { name: "Create source" }));

    expect(apiMock.createDiscoverySource).toHaveBeenCalledWith({
      name: "service-accounts",
      kind: "service_account",
      config: {
        accounts: [
          expect.objectContaining({ surface: "active_directory", provider: "ad" }),
          expect.objectContaining({ surface: "cloud", provider: "aws-iam", privileged: true }),
        ],
      },
    });
  });

  it("creates an NHI behavior source from metadata-only activity events", async () => {
    const user = userEvent.setup();
    renderDiscovery(["/discovery?tab=sources"]);

    await screen.findByRole("heading", { name: "Import sanitized observations" });
    const sourceForm = screen.getByRole("heading", { name: "Import sanitized observations" }).closest("form");
    expect(sourceForm).toBeTruthy();
    await user.type(within(sourceForm as HTMLFormElement).getByLabelText("Name"), "behavior-quarterly");
    await user.selectOptions(within(sourceForm as HTMLFormElement).getByLabelText("Kind"), "nhi_behavior");
    await user.click(within(sourceForm as HTMLFormElement).getByRole("button", { name: "Advanced JSON import" }));
    fireEvent.change(within(sourceForm as HTMLFormElement).getByLabelText("NHI behavior JSON import"), {
      target: {
        value: JSON.stringify([
          {
            principal: "payments-api",
            occurred_at: "2026-06-01T10:00:00Z",
            ip: "198.51.100.10",
            geo: "US",
            user_agent: "payments-agent/1.0",
            usage_count: 10,
            baseline: true,
          },
          {
            principal: "payments-api",
            occurred_at: "2026-06-02T02:15:00Z",
            ip: "203.0.113.9",
            geo: "DE",
            user_agent: "curl/8.7",
            usage_count: 90,
          },
        ]),
      },
    });
    await user.click(within(sourceForm as HTMLFormElement).getByRole("button", { name: "Create source" }));

    expect(apiMock.createDiscoverySource).toHaveBeenCalledWith({
      name: "behavior-quarterly",
      kind: "nhi_behavior",
      config: {
        business_hours: { start_hour: 8, end_hour: 18 },
        events: [expect.objectContaining({ principal: "payments-api", baseline: true }), expect.objectContaining({ principal: "payments-api", geo: "DE" })],
      },
    });
  });

  it("creates a compromised-credential source from metadata-only external signals", async () => {
    const user = userEvent.setup();
    renderDiscovery(["/discovery?tab=sources"]);

    await screen.findByRole("heading", { name: "Import sanitized observations" });
    const sourceForm = screen.getByRole("heading", { name: "Import sanitized observations" }).closest("form");
    expect(sourceForm).toBeTruthy();
    await user.type(within(sourceForm as HTMLFormElement).getByLabelText("Name"), "compromise-signals");
    await user.selectOptions(within(sourceForm as HTMLFormElement).getByLabelText("Kind"), "credential_compromise");
    await user.click(within(sourceForm as HTMLFormElement).getByRole("button", { name: "Advanced JSON import" }));
    fireEvent.change(within(sourceForm as HTMLFormElement).getByLabelText("Compromised credentials JSON import"), {
      target: {
        value: JSON.stringify([
          {
            principal: "payments-api",
            credential_ref: "api-token:payments-ci",
            credential_kind: "api_token",
            provider: "github-actions",
            detector: "honeytoken",
            observed_at: "2026-06-03T03:15:00Z",
            reason: "revoked token replayed from unfamiliar network",
            confidence: "critical",
            evidence_refs: ["audit:api-token-use/evt-42"],
          },
        ]),
      },
    });
    await user.click(within(sourceForm as HTMLFormElement).getByRole("button", { name: "Create source" }));

    expect(apiMock.createDiscoverySource).toHaveBeenCalledWith({
      name: "compromise-signals",
      kind: "credential_compromise",
      config: {
        signals: [
          expect.objectContaining({
            principal: "payments-api",
            credential_ref: "api-token:payments-ci",
            detector: "honeytoken",
          }),
        ],
      },
    });
  });

  it("creates a Kubernetes ingress/gateway source from metadata-only TLS resources", async () => {
    const user = userEvent.setup();
    renderDiscovery(["/discovery?tab=sources"]);

    await screen.findByRole("heading", { name: "Import sanitized observations" });
    const sourceForm = screen.getByRole("heading", { name: "Import sanitized observations" }).closest("form");
    expect(sourceForm).toBeTruthy();
    await user.type(within(sourceForm as HTMLFormElement).getByLabelText("Name"), "k8s-tls");
    await user.selectOptions(within(sourceForm as HTMLFormElement).getByLabelText("Kind"), "k8s_ingress_gateway");
    await user.click(within(sourceForm as HTMLFormElement).getByRole("button", { name: "Advanced JSON import" }));
    fireEvent.change(within(sourceForm as HTMLFormElement).getByLabelText("Kubernetes TLS JSON import"), {
      target: {
        value: JSON.stringify([
          {
            kind: "Ingress",
            namespace: "payments",
            name: "payments-web",
            tls_secret_name: "payments-web-tls",
            hosts: ["payments.example.com"],
            auto_issue: true,
          },
          {
            kind: "Gateway",
            namespace: "edge",
            name: "public",
            tls_secret_name: "edge-public-tls",
            hosts: ["edge.example.com", "api.example.com"],
            auto_issue: true,
          },
        ]),
      },
    });
    await user.click(within(sourceForm as HTMLFormElement).getByRole("button", { name: "Create source" }));

    expect(apiMock.createDiscoverySource).toHaveBeenCalledWith({
      name: "k8s-tls",
      kind: "k8s_ingress_gateway",
      config: {
        resources: [
          expect.objectContaining({ kind: "Ingress", namespace: "payments", tls_secret_name: "payments-web-tls" }),
          expect.objectContaining({ kind: "Gateway", namespace: "edge", tls_secret_name: "edge-public-tls" }),
        ],
      },
    });
  });

  it("uses permission and empty states when discovery records are unavailable or absent", async () => {
    apiMock.discoverySources.mockRejectedValueOnce(new ApiError(403, JSON.stringify({ detail: "missing discovery:read" })));
    apiMock.discoverySchedules.mockResolvedValueOnce({ items: [] });
    apiMock.discoveryRuns.mockResolvedValueOnce({ items: [] });
    apiMock.discoveryFindings.mockResolvedValueOnce({ items: [] });
    const user = userEvent.setup();
    renderDiscovery();

    expect(await screen.findByText("Permission denied")).toBeInTheDocument();
    expect(screen.getByText("missing discovery:read")).toBeInTheDocument();
    expect(screen.getByText("No discovery findings")).toBeInTheDocument();
    await user.click(screen.getByRole("tab", { name: "Schedules" }));
    expect(screen.getByText("No discovery schedules")).toBeInTheDocument();
    await user.click(screen.getByRole("tab", { name: "Runs" }));
    expect(screen.getByText("No discovery runs")).toBeInTheDocument();
  });

  it("AUD-71 renders the served failure detail and parent refresh reloads CT state", async () => {
    apiMock.discoveryRuns.mockResolvedValueOnce({
      items: [
        {
          id: "run-failed",
          tenant_id: "tenant-1",
          source_id: "source-1",
          status: "failed",
          dry_run: false,
          execution: "control_plane",
          targets: 1,
          discovered: 0,
          failed: 1,
          rejected: 0,
          blocked: 0,
          error: "ctmonitor: GET /ct/v1/get-sth: 404 Not Found",
          created_at: "2026-06-20T10:02:00Z",
          completed_at: "2026-06-20T10:02:05Z",
        },
      ],
    });
    const user = userEvent.setup();
    renderDiscovery(["/discovery?tab=runs"]);

    expect(await screen.findByText("ctmonitor: GET /ct/v1/get-sth: 404 Not Found")).toBeInTheDocument();
    await user.click(screen.getByRole("tab", { name: "What was found" }));
    await waitFor(() => expect(apiMock.ctMonitoring).toHaveBeenCalledTimes(1));
    await user.click(screen.getByRole("button", { name: "Refresh" }));
    await waitFor(() => expect(apiMock.ctMonitoring).toHaveBeenCalledTimes(2));
  });
});
