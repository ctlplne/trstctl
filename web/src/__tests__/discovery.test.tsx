import { beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { ApiError } from "@/lib/api";
import { Discovery } from "@/pages/Discovery";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    discoverySources: vi.fn(),
    discoverySchedules: vi.fn(),
    discoveryRuns: vi.fn(),
    discoveryMonitoring: vi.fn(),
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
    const monitoring = screen.getByRole("heading", { name: "Continuous monitoring" }).closest("section");
    expect(monitoring).toBeTruthy();
    expect(within(monitoring as HTMLElement).getByText("Scheduled")).toBeInTheDocument();
    expect(within(monitoring as HTMLElement).getByText("1h")).toBeInTheDocument();
    expect(within(monitoring as HTMLElement).getByText("/api/v1/certificates")).toBeInTheDocument();
    expect(within(monitoring as HTMLElement).getByText("/api/v1/discovery/findings?run_id=run-1")).toBeInTheDocument();
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

  it("creates a cross-surface NHI source from metadata-only observations", async () => {
    const user = userEvent.setup();
    renderDiscovery();

    await screen.findByRole("heading", { name: "Source" });
    const sourceForm = screen.getByRole("heading", { name: "Source" }).closest("form");
    expect(sourceForm).toBeTruthy();
    await user.type(within(sourceForm as HTMLFormElement).getByLabelText("Name"), "nhi-quarterly");
    await user.selectOptions(within(sourceForm as HTMLFormElement).getByLabelText("Kind"), "nhi_cross_surface");
    fireEvent.change(within(sourceForm as HTMLFormElement).getByLabelText("Observations JSON"), {
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

  it("creates an API-key and token source from metadata-only observations", async () => {
    const user = userEvent.setup();
    renderDiscovery();

    await screen.findByRole("heading", { name: "Source" });
    const sourceForm = screen.getByRole("heading", { name: "Source" }).closest("form");
    expect(sourceForm).toBeTruthy();
    await user.type(within(sourceForm as HTMLFormElement).getByLabelText("Name"), "tokens-quarterly");
    await user.selectOptions(within(sourceForm as HTMLFormElement).getByLabelText("Kind"), "api_key");
    fireEvent.change(within(sourceForm as HTMLFormElement).getByLabelText("Observations JSON"), {
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
    renderDiscovery();

    await screen.findByRole("heading", { name: "Source" });
    const sourceForm = screen.getByRole("heading", { name: "Source" }).closest("form");
    expect(sourceForm).toBeTruthy();
    await user.type(within(sourceForm as HTMLFormElement).getByLabelText("Name"), "oauth-quarterly");
    await user.selectOptions(within(sourceForm as HTMLFormElement).getByLabelText("Kind"), "oauth_grant");
    fireEvent.change(within(sourceForm as HTMLFormElement).getByLabelText("OAuth grants JSON"), {
      target: {
        value: JSON.stringify([
          {
            provider: "okta",
            app_id: "0oa-payments",
            app_name: "Payments BI Export",
            principal: "payments-bi-export",
            resource: "google-workspace",
            scopes: ["drive.readonly", "admin.directory.user.readonly"],
            consent_type: "admin",
            third_party: true,
            owner: "finance-platform",
            publisher_verified: false,
            threat_signals: ["consent_phishing"],
            evidence_refs: ["okta:audit/consent-42"],
          },
        ]),
      },
    });
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
    renderDiscovery();

    await screen.findByRole("heading", { name: "Source" });
    const sourceForm = screen.getByRole("heading", { name: "Source" }).closest("form");
    expect(sourceForm).toBeTruthy();
    await user.type(within(sourceForm as HTMLFormElement).getByLabelText("Name"), "service-accounts");
    await user.selectOptions(within(sourceForm as HTMLFormElement).getByLabelText("Kind"), "service_account");
    fireEvent.change(within(sourceForm as HTMLFormElement).getByLabelText("Service accounts JSON"), {
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
    renderDiscovery();

    await screen.findByRole("heading", { name: "Source" });
    const sourceForm = screen.getByRole("heading", { name: "Source" }).closest("form");
    expect(sourceForm).toBeTruthy();
    await user.type(within(sourceForm as HTMLFormElement).getByLabelText("Name"), "behavior-quarterly");
    await user.selectOptions(within(sourceForm as HTMLFormElement).getByLabelText("Kind"), "nhi_behavior");
    fireEvent.change(within(sourceForm as HTMLFormElement).getByLabelText("Behavior events JSON"), {
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
        events: [
          expect.objectContaining({ principal: "payments-api", baseline: true }),
          expect.objectContaining({ principal: "payments-api", geo: "DE" }),
        ],
      },
    });
  });

  it("creates a compromised-credential source from metadata-only external signals", async () => {
    const user = userEvent.setup();
    renderDiscovery();

    await screen.findByRole("heading", { name: "Source" });
    const sourceForm = screen.getByRole("heading", { name: "Source" }).closest("form");
    expect(sourceForm).toBeTruthy();
    await user.type(within(sourceForm as HTMLFormElement).getByLabelText("Name"), "compromise-signals");
    await user.selectOptions(within(sourceForm as HTMLFormElement).getByLabelText("Kind"), "credential_compromise");
    fireEvent.change(within(sourceForm as HTMLFormElement).getByLabelText("Compromise signals JSON"), {
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
    renderDiscovery();

    await screen.findByRole("heading", { name: "Source" });
    const sourceForm = screen.getByRole("heading", { name: "Source" }).closest("form");
    expect(sourceForm).toBeTruthy();
    await user.type(within(sourceForm as HTMLFormElement).getByLabelText("Name"), "k8s-tls");
    await user.selectOptions(within(sourceForm as HTMLFormElement).getByLabelText("Kind"), "k8s_ingress_gateway");
    fireEvent.change(within(sourceForm as HTMLFormElement).getByLabelText("Kubernetes resources JSON"), {
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
    renderDiscovery();

    expect(await screen.findByText("Permission denied")).toBeInTheDocument();
    expect(screen.getByText("missing discovery:read")).toBeInTheDocument();
    expect(screen.getByText("No discovery schedules")).toBeInTheDocument();
    expect(screen.getByText("No discovery runs")).toBeInTheDocument();
    expect(screen.getByText("No discovery findings")).toBeInTheDocument();
  });
});
