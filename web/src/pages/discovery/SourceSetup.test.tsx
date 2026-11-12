import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { AppQueryProvider } from "@/lib/query";
import { SourceSetup, parsePorts, sourceWizardContractProblems, sourceWizardFieldPaths, type PrimaryKind } from "./SourceSetup";
import { ApiError, type DiscoveryCapability, type DiscoveryCapabilityCatalog, type DiscoveryCoverage, type DiscoverySource } from "@/lib/api";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    agents: vi.fn(),
    discoveryCapabilities: vi.fn(),
    discoveryCoverage: vi.fn(),
    createDiscoverySegment: vi.fn(),
    previewDiscoveryPlan: vi.fn(),
    createDiscoverySource: vi.fn(),
  },
}));

vi.mock("@/lib/api", async (original) => {
  const actual = await original<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...apiMock } };
});

function capability(kind: PrimaryKind, providers?: DiscoveryCapability["providers"]): DiscoveryCapability {
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

const catalog: DiscoveryCapabilityCatalog = {
  schema_version: 1,
  items: [
    capability("network"),
    capability("cloud_machine_entitlement"),
    capability("gcp_machine_identity"),
    capability("azure_machine_identity"),
    capability("ssh"),
    capability("ssh_trust"),
    capability("adcs"),
    capability("cloud_certificate", [
      { id: "aws-acm", label: "AWS Certificate Manager", least_privilege: "List certificates", preferred_credential: "env: references", fields: [] },
    ]),
    capability("cloud_secret", [
      {
        id: "aws-secrets-manager",
        label: "AWS Secrets Manager",
        least_privilege: "ListSecrets on the approved scope",
        preferred_credential: "env: references",
        fields: ["region", "access_key_id_ref", "secret_access_key_ref"],
      },
    ]),
    capability("secret_store", [
      { id: "hashicorp-vault", label: "HashiCorp Vault", least_privilege: "List metadata", preferred_credential: "token_ref", fields: [] },
      { id: "github-actions", label: "GitHub Actions secrets", least_privilege: "Secrets read", preferred_credential: "token_ref", fields: [] },
      { id: "gitlab-ci", label: "GitLab CI/CD variables", least_privilege: "read_api", preferred_credential: "token_ref", fields: [] },
      { id: "infisical", label: "Infisical secrets", least_privilege: "Viewer", preferred_credential: "client_secret_ref", fields: [] },
      { id: "conjur", label: "CyberArk Conjur variables", least_privilege: "read", preferred_credential: "api_key_ref", fields: [] },
      { id: "akeyless", label: "Akeyless static secrets", least_privilege: "list", preferred_credential: "client_secret_ref", fields: [] },
      { id: "bitwarden-secrets-manager", label: "Bitwarden Secrets Manager secrets", least_privilege: "read", preferred_credential: "token_ref", fields: [] },
      { id: "1password-connect", label: "1Password Connect items", least_privilege: "read", preferred_credential: "token_ref", fields: [] },
      { id: "doppler", label: "Doppler secrets", least_privilege: "read", preferred_credential: "token_ref", fields: [] },
    ]),
  ],
};

const emptyCoverage: DiscoveryCoverage = {
  classes: [],
  generated_at: "2026-08-25T00:00:00Z",
  observed: 0,
  provenance: { total: 0, observed: 0, stale: 0, never_observed: 0, stale_after_hours: 168 },
  segment_coverage_percent: 0,
  segments: [],
  structurally_unobservable: 0,
  unknowns: [],
  unobserved: 0,
};

function renderSetup(onCreated = vi.fn()) {
  return render(
    <AppQueryProvider>
      <SourceSetup onCreated={onCreated} />
    </AppQueryProvider>,
  );
}

describe("typed discovery source setup", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    apiMock.agents.mockResolvedValue([{ id: "a2270000-0000-4000-8000-000000000001", name: "SSH relay", roles: ["network"] }]);
    apiMock.discoveryCapabilities.mockResolvedValue(catalog);
    apiMock.discoveryCoverage.mockResolvedValue(emptyCoverage);
    apiMock.createDiscoverySegment.mockResolvedValue({
      id: "segment-1",
      name: "production-edge",
      ranges: ["api.example.test", "10.20.30.0/30"],
      staleness_hours: 168,
      excluded: false,
      last_found_count: 0,
      created_at: "2026-08-25T00:00:00Z",
    });
    apiMock.previewDiscoveryPlan.mockResolvedValue({
      kind: "network",
      ready: true,
      execution: "network-role relay",
      protocol: "tls",
      connection_origin: "eligible active network-role relay",
      segment: "production-edge",
      normalized_targets: ["api.example.test:443", "api.example.test:8443", "api.example.test:8444"],
      normalized_target_count: 3,
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
    apiMock.createDiscoverySource.mockResolvedValue({
      id: "source-1",
      tenant_id: "tenant-1",
      name: "Production TLS",
      kind: "network",
      config: {},
      created_at: "2026-08-25T00:00:00Z",
      updated_at: "2026-08-25T00:00:00Z",
    } satisfies DiscoverySource);
  });

  it("reviews and saves one exact workload IAM check with unknown context and reference-only custody", async () => {
    const user = userEvent.setup();
    renderSetup();
    await screen.findByText("What this source does");
    await user.type(screen.getByRole("textbox", { name: "Source name" }), "Owned workload IAM");
    await user.selectOptions(screen.getByRole("combobox", { name: "What should trstctl inspect?" }), "cloud_machine_entitlement");
    await user.type(screen.getByRole("textbox", { name: "Workload IAM name" }), "workload");
    await user.type(screen.getByRole("textbox", { name: "Exact principal ARN" }), "arn:aws:iam::111122223333:user/workload");
    await user.type(screen.getByRole("textbox", { name: "Approved STS session file reference" }), "env:TRSTCTL_AWS_READER_SESSION_PATH");
    await user.type(screen.getByRole("textbox", { name: "Resource ARN or global marker" }), "arn:aws:s3:::owned/report");
    await user.type(screen.getByRole("textbox", { name: "Resource owner account ID" }), "111122223333");
    await user.click(screen.getByRole("button", { name: "Review exact plan" }));
    await waitFor(() =>
      expect(apiMock.previewDiscoveryPlan).toHaveBeenCalledWith(
        expect.objectContaining({
          kind: "cloud_machine_entitlement",
          config: expect.objectContaining({
            session_file_ref: "env:TRSTCTL_AWS_READER_SESSION_PATH",
            principals: [{ kind: "iam_user", name: "workload" }],
            assessment: expect.objectContaining({
              checks: [expect.objectContaining({ action: "s3:GetObject", context: { values: {}, complete: false } })],
              recorded_policy_evidence: [],
              recorded_activity_evidence: {},
            }),
          }),
        }),
      ),
    );
    await user.click(await screen.findByRole("button", { name: "Save source" }));
    await waitFor(() => expect(apiMock.createDiscoverySource).toHaveBeenCalledWith(expect.objectContaining({ kind: "cloud_machine_entitlement" })));
  });

  it("reviews and saves selected GCP workload accounts with reference-only reader custody", async () => {
    const user = userEvent.setup();
    renderSetup();
    await screen.findByText("What this source does");
    await user.type(screen.getByRole("textbox", { name: "Source name" }), "Owned GCP workload inventory");
    await user.selectOptions(screen.getByRole("combobox", { name: "What should trstctl inspect?" }), "gcp_machine_identity");
    await user.type(screen.getByLabelText("Workload project ID"), "owned-project");
    await user.type(screen.getByLabelText("Selected service-account emails"), "orders@owned-project.iam.gserviceaccount.com");
    await user.type(screen.getByLabelText("Approved GCP token file reference"), "env:TRSTCTL_GCP_READER_TOKEN_FILE");
    await user.click(screen.getByRole("button", { name: "Review exact plan" }));
    await waitFor(() =>
      expect(apiMock.previewDiscoveryPlan).toHaveBeenCalledWith(
        expect.objectContaining({
          kind: "gcp_machine_identity",
          config: expect.objectContaining({
            project: "owned-project",
            service_accounts: ["orders@owned-project.iam.gserviceaccount.com"],
            token_file_ref: "env:TRSTCTL_GCP_READER_TOKEN_FILE",
            activity_lookback_days: 30,
          }),
        }),
      ),
    );
    await user.click(await screen.findByRole("button", { name: "Save source" }));
    await waitFor(() => expect(apiMock.createDiscoverySource).toHaveBeenCalledWith(expect.objectContaining({ kind: "gcp_machine_identity" })));
  });
  it("reviews Azure workloads with separate Graph and ARM file references", async () => {
    const user = userEvent.setup();
    renderSetup();
    await screen.findByText("What this source does");
    await user.type(screen.getByRole("textbox", { name: "Source name" }), "Owned Azure workload inventory");
    await user.selectOptions(screen.getByRole("combobox", { name: "What should trstctl inspect?" }), "azure_machine_identity");
    await user.type(screen.getByLabelText("Azure tenant UUID"), "10000000-0000-0000-0000-000000000001");
    await user.type(screen.getByLabelText("Azure subscription UUID"), "20000000-0000-0000-0000-000000000002");
    await user.type(screen.getByLabelText("Selected service-principal object UUIDs"), "30000000-0000-0000-0000-000000000003");
    await user.type(screen.getByLabelText("Approved Graph token file reference"), "env:OWNED_GRAPH_FILE");
    await user.type(screen.getByLabelText("Approved ARM token file reference"), "env:OWNED_ARM_FILE");
    await user.click(screen.getByRole("button", { name: "Review exact plan" }));
    await waitFor(() =>
      expect(apiMock.previewDiscoveryPlan).toHaveBeenCalledWith(
        expect.objectContaining({
          kind: "azure_machine_identity",
          config: expect.objectContaining({
            graph_token_file_ref: "env:OWNED_GRAPH_FILE",
            arm_token_file_ref: "env:OWNED_ARM_FILE",
            read_beta_signins: false,
            activity_lookback_days: 0,
            service_principal_ids: ["30000000-0000-0000-0000-000000000003"],
          }),
        }),
      ),
    );
    await user.click(await screen.findByRole("button", { name: "Save source" }));
    await waitFor(() => expect(apiMock.createDiscoverySource).toHaveBeenCalledWith(expect.objectContaining({ kind: "azure_machine_identity" })));
  });
  it("requires explicit agentless opt-in and submits pinned hosts with references only", async () => {
    const user = userEvent.setup();
    apiMock.discoveryCoverage.mockResolvedValue({
      ...emptyCoverage,
      segments: [{ name: "ssh-owned", ranges: ["ssh.example.test"], status: "never", staleness_hours: 168 }],
    });
    renderSetup();
    await screen.findByText("What this source does");
    await user.type(screen.getByRole("textbox", { name: "Source name" }), "Owned SSH trust");
    await user.selectOptions(screen.getByRole("combobox", { name: "What should trstctl inspect?" }), "ssh_trust");
    await user.click(screen.getByRole("button", { name: "Review exact plan" }));
    expect(await screen.findByText("Explicitly enable agentless SSH collection.")).toBeInTheDocument();
    expect(apiMock.previewDiscoveryPlan).not.toHaveBeenCalled();
    await user.click(screen.getByRole("checkbox", { name: "Enable read-only agentless SSH collection" }));
    await user.selectOptions(screen.getByRole("combobox", { name: "Declared SSH scope" }), "ssh-owned");
    await user.selectOptions(screen.getByRole("combobox", { name: "Collecting network relay" }), "a2270000-0000-4000-8000-000000000001");
    await user.type(screen.getByRole("textbox", { name: "SSH host:port" }), "ssh.example.test:22");
    await user.type(screen.getByRole("textbox", { name: "Trusted host-key fingerprint" }), "SHA256:" + "A".repeat(43));
    await user.type(screen.getByRole("textbox", { name: "Vault key reference" }), "secret://ssh/reader");
    await user.click(screen.getByRole("button", { name: "Review exact plan" }));
    await waitFor(() =>
      expect(apiMock.previewDiscoveryPlan).toHaveBeenCalledWith(
        expect.objectContaining({
          kind: "ssh_trust",
          config: {
            enabled: true,
            segment: "ssh-owned",
            relay_agent_id: "a2270000-0000-4000-8000-000000000001",
            allow_rfc1918: false,
            allow_loopback: false,
            hosts: [
              {
                address: "ssh.example.test:22",
                username: "trstctl_observe",
                host_key_fingerprint: "SHA256:" + "A".repeat(43),
                credential_ref: "secret://ssh/reader",
              },
            ],
          },
        }),
      ),
    );
    expect(apiMock.createDiscoverySegment).not.toHaveBeenCalled();
  });

  it("requires a relay and DNS grant before endpoint probes enter the preview", async () => {
    const user = userEvent.setup();
    renderSetup();
    await screen.findByText("What this source does");
    await user.type(screen.getByRole("textbox", { name: "Source name" }), "Directory endpoint assessment");
    await user.selectOptions(screen.getByRole("combobox", { name: "What should trstctl inspect?" }), "adcs");
    const toggle = screen.getByRole("checkbox", { name: /Probe enrollment paths from directory hostnames/ });
    expect(toggle).not.toBeChecked();
    await user.click(toggle);
    await user.click(screen.getByRole("button", { name: "Review exact plan" }));
    expect(await screen.findByText("Select an upgraded network relay for endpoint probing.")).toBeInTheDocument();
    expect(apiMock.previewDiscoveryPlan).not.toHaveBeenCalled();
    for (const [name, value] of [
      ["Directory URL", "dc.corp.example"],
      ["Configuration naming context", "CN=Configuration,DC=corp,DC=example"],
      ["Bind identity", "CN=reader,DC=corp,DC=example"],
      ["Password reference", "secret://adcs/reader"],
      ["Allowed endpoint DNS suffixes", "corp.example, CORP.EXAMPLE."],
    ]) {
      await user.type(screen.getByRole("textbox", { name }), value);
    }
    await user.type(screen.getByRole("combobox", { name: "Network relay" }), "a2270000-0000-4000-8000-000000000001");
    await user.click(screen.getByRole("button", { name: "Review exact plan" }));
    await waitFor(() =>
      expect(apiMock.previewDiscoveryPlan).toHaveBeenCalledWith(
        expect.objectContaining({
          kind: "adcs",
          config: expect.objectContaining({
            endpoint_probe: { enabled: true, dns_suffixes: ["corp.example"] },
            relay_agent_id: "a2270000-0000-4000-8000-000000000001",
          }),
        }),
      ),
    );
    expect(JSON.stringify(apiMock.previewDiscoveryPlan.mock.calls)).not.toContain("previous_probe_page");
  });

  it("normalizes a bounded host/CIDR/port plan and submits every configured field", async () => {
    const user = userEvent.setup();
    const onCreated = vi.fn();
    renderSetup(onCreated);

    expect(await screen.findByText("What this source does")).toBeInTheDocument();
    await user.type(screen.getByRole("textbox", { name: "Source name" }), "Production TLS");
    await user.type(screen.getByRole("textbox", { name: "Authorized scope" }), "production-edge");
    await user.type(screen.getByRole("textbox", { name: /Hosts, IPs/ }), "api.example.test");
    await user.type(screen.getByRole("textbox", { name: "CIDR ranges" }), "10.20.30.0/30");
    const ports = screen.getByRole("textbox", { name: "Ports" });
    await user.clear(ports);
    await user.type(ports, "443, 8443-8444");

    await user.click(screen.getByRole("button", { name: "Declare scope and review plan" }));
    expect(await screen.findByRole("region", { name: "Normalized discovery plan" })).toHaveTextContent("3");
    expect(apiMock.createDiscoverySegment).toHaveBeenCalledWith({
      name: "production-edge",
      ranges: ["api.example.test", "10.20.30.0/30"],
      staleness_hours: 168,
    });
    expect(apiMock.previewDiscoveryPlan).toHaveBeenCalledWith(
      expect.objectContaining({
        kind: "network",
        config: expect.objectContaining({ segment: "production-edge", ports: [443, 8443, 8444] }),
      }),
    );
    await user.click(screen.getByRole("button", { name: "Save source" }));

    await waitFor(() =>
      expect(apiMock.createDiscoverySource).toHaveBeenCalledWith({
        name: "Production TLS",
        kind: "network",
        config: {
          targets: ["api.example.test:443", "api.example.test:8443", "api.example.test:8444"],
          cidrs: ["10.20.30.0/30"],
          ports: [443, 8443, 8444],
          segment: "production-edge",
        },
      }),
    );
    expect(onCreated).toHaveBeenCalledWith(expect.objectContaining({ id: "source-1" }));
  });

  it("shows the exact server blocker while still allowing the source definition to be saved", async () => {
    const user = userEvent.setup();
    apiMock.previewDiscoveryPlan.mockResolvedValueOnce({
      kind: "network",
      ready: false,
      execution: "network-role relay",
      protocol: "tls",
      connection_origin: "No network relay is enrolled",
      segment: "production-edge",
      normalized_targets: ["api.example.test:443"],
      normalized_target_count: 1,
      preview_truncated: false,
      excluded_target_count: 0,
      child_job_count: 1,
      concurrency: 16,
      queue_depth: 256,
      estimated_upper_seconds: 10,
      permission: "discovery:write",
      data_handling: "Public metadata only.",
      side_effects: false,
      blocked_reasons: ["Enroll an agent with the network role before starting this source."],
    });
    renderSetup();

    await user.type(await screen.findByRole("textbox", { name: "Source name" }), "Production TLS");
    await user.type(screen.getByRole("textbox", { name: "Authorized scope" }), "production-edge");
    await user.type(screen.getByRole("textbox", { name: /Hosts, IPs/ }), "api.example.test");
    await user.click(screen.getByRole("button", { name: "Declare scope and review plan" }));

    expect(await screen.findByRole("alert")).toHaveTextContent("Run blocked");
    expect(screen.getByRole("alert")).toHaveTextContent("Enroll an agent with the network role before starting this source.");
    expect(screen.getByRole("button", { name: "Save source" })).toBeEnabled();
  });

  it("round-trips cloud credential references without rendering their full names in review", async () => {
    const user = userEvent.setup();
    renderSetup();

    await screen.findByText("What this source does");
    await user.selectOptions(screen.getByRole("combobox", { name: "What should trstctl inspect?" }), "cloud_secret");
    await user.type(screen.getByRole("textbox", { name: "Source name" }), "Production secret metadata");
    await user.type(screen.getByRole("textbox", { name: "Region" }), "us-east-1");
    await user.type(screen.getByRole("textbox", { name: "Access key ID reference" }), "env:DISCOVERY_ACCESS_KEY");
    await user.type(screen.getByRole("textbox", { name: "Secret access key reference" }), "env:DISCOVERY_SECRET_KEY");
    await user.type(screen.getByRole("textbox", { name: "Optional AWS tag key" }), "environment");
    await user.type(screen.getByRole("textbox", { name: "Optional AWS tag value" }), "production");
    await user.click(screen.getByRole("button", { name: "Review exact plan" }));

    const exact = await screen.findByText("Exact redacted configuration");
    await user.click(exact);
    expect(screen.getByText(/env:…/)).toBeInTheDocument();
    expect(screen.queryByText(/DISCOVERY_SECRET_KEY/)).not.toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Save source" }));
    await waitFor(() =>
      expect(apiMock.createDiscoverySource).toHaveBeenCalledWith(
        expect.objectContaining({
          kind: "cloud_secret",
          config: expect.objectContaining({
            providers: [
              expect.objectContaining({
                provider: "aws-secrets-manager",
                region: "us-east-1",
                access_key_id_ref: "env:DISCOVERY_ACCESS_KEY",
                secret_access_key_ref: "env:DISCOVERY_SECRET_KEY",
                tag_key: "environment",
                tag_value: "production",
              }),
            ],
          }),
        }),
      ),
    );
  });

  it("configures a code-host secret store and refuses GitHub content inspection", async () => {
    const user = userEvent.setup();
    renderSetup();

    await screen.findByText("What this source does");
    await user.selectOptions(screen.getByRole("combobox", { name: "What should trstctl inspect?" }), "secret_store");
    await user.type(screen.getByRole("textbox", { name: "Source name" }), "CI secrets");
    await user.selectOptions(screen.getByRole("combobox", { name: "Provider" }), "github-actions");
    await user.type(screen.getByRole("textbox", { name: "GitHub owner" }), "acme");
    await user.type(screen.getByRole("textbox", { name: "GitHub repository" }), "api");
    await user.type(screen.getByRole("textbox", { name: /GitHub environments/ }), "production, staging");
    await user.type(screen.getByRole("textbox", { name: /Token reference/ }), "env:GITHUB_DISCOVERY_TOKEN");
    await user.click(screen.getByRole("checkbox", { name: /Inspect secret content/ }));
    await user.click(screen.getByRole("button", { name: "Review exact plan" }));
    expect(await screen.findByText(/GitHub never returns secret values. Turn content inspection off/)).toBeInTheDocument();
    expect(apiMock.createDiscoverySource).not.toHaveBeenCalled();

    await user.click(screen.getByRole("checkbox", { name: /Inspect secret content/ }));
    await user.click(screen.getByRole("button", { name: "Review exact plan" }));
    await user.click(await screen.findByRole("button", { name: "Save source" }));
    await waitFor(() =>
      expect(apiMock.createDiscoverySource).toHaveBeenCalledWith(
        expect.objectContaining({
          kind: "secret_store",
          config: {
            providers: [
              { provider: "github-actions", owner: "acme", repo: "api", environments: ["production", "staging"], token_ref: "env:GITHUB_DISCOVERY_TOKEN" },
            ],
          },
        }),
      ),
    );
  });

  it("lists GitHub Dependabot and Codespaces secrets beside Actions secrets (OD-2)", async () => {
    const user = userEvent.setup();
    renderSetup();

    await screen.findByText("What this source does");
    await user.selectOptions(screen.getByRole("combobox", { name: "What should trstctl inspect?" }), "secret_store");
    await user.type(screen.getByRole("textbox", { name: "Source name" }), "Code host stores");
    await user.selectOptions(screen.getByRole("combobox", { name: "Provider" }), "github-actions");
    await user.type(screen.getByRole("textbox", { name: "GitHub owner" }), "acme");
    await user.type(screen.getByRole("textbox", { name: "GitHub repository" }), "api");
    await user.type(screen.getByRole("textbox", { name: /Token reference/ }), "env:GITHUB_DISCOVERY_TOKEN");
    expect(screen.getByRole("checkbox", { name: "Actions" })).toBeChecked();

    // A repository with no store chosen is refused before review.
    await user.click(screen.getByRole("checkbox", { name: "Actions" }));
    await user.click(screen.getByRole("button", { name: "Review exact plan" }));
    expect(await screen.findByText("Choose at least one secret store for the repository or organization.")).toBeInTheDocument();

    // Environment secrets are Actions secrets.
    await user.click(screen.getByRole("checkbox", { name: "Dependabot" }));
    await user.click(screen.getByRole("checkbox", { name: "Codespaces" }));
    await user.type(screen.getByRole("textbox", { name: /GitHub environments/ }), "production");
    await user.click(screen.getByRole("button", { name: "Review exact plan" }));
    expect(await screen.findByText(/Environment secrets are Actions secrets/)).toBeInTheDocument();
    expect(apiMock.createDiscoverySource).not.toHaveBeenCalled();

    await user.clear(screen.getByRole("textbox", { name: /GitHub environments/ }));
    await user.click(screen.getByRole("checkbox", { name: /The token owner's Codespaces secrets/ }));
    await user.click(screen.getByRole("button", { name: "Review exact plan" }));
    await user.click(await screen.findByRole("button", { name: "Save source" }));
    await waitFor(() =>
      expect(apiMock.createDiscoverySource).toHaveBeenCalledWith(
        expect.objectContaining({
          kind: "secret_store",
          config: {
            providers: [
              {
                provider: "github-actions",
                owner: "acme",
                repo: "api",
                stores: ["dependabot", "codespaces"],
                user_codespaces: true,
                token_ref: "env:GITHUB_DISCOVERY_TOKEN",
              },
            ],
          },
        }),
      ),
    );
  });

  it("lists GitLab instance variables without a project or group (OD-2)", async () => {
    const user = userEvent.setup();
    renderSetup();

    await screen.findByText("What this source does");
    await user.selectOptions(screen.getByRole("combobox", { name: "What should trstctl inspect?" }), "secret_store");
    await user.type(screen.getByRole("textbox", { name: "Source name" }), "Instance variables");
    await user.selectOptions(screen.getByRole("combobox", { name: "Provider" }), "gitlab-ci");
    await user.type(screen.getByRole("textbox", { name: /Token reference/ }), "env:GITLAB_ADMIN_TOKEN");
    await user.click(screen.getByRole("button", { name: "Review exact plan" }));
    expect(await screen.findByText("Enter a GitLab project or group, or choose the instance variables.")).toBeInTheDocument();
    expect(apiMock.createDiscoverySource).not.toHaveBeenCalled();

    await user.click(screen.getByRole("checkbox", { name: /Instance variables/ }));
    await user.click(screen.getByRole("button", { name: "Review exact plan" }));
    await user.click(await screen.findByRole("button", { name: "Save source" }));
    await waitFor(() =>
      expect(apiMock.createDiscoverySource).toHaveBeenCalledWith(
        expect.objectContaining({
          kind: "secret_store",
          config: { providers: [{ provider: "gitlab-ci", instance: true, token_ref: "env:GITLAB_ADMIN_TOKEN" }] },
        }),
      ),
    );
  });

  it("configures a Conjur store with its own sign-in instead of a token reference (OD-13)", async () => {
    const user = userEvent.setup();
    renderSetup();

    await screen.findByText("What this source does");
    await user.selectOptions(screen.getByRole("combobox", { name: "What should trstctl inspect?" }), "secret_store");
    await user.type(screen.getByRole("textbox", { name: "Source name" }), "Conjur variables");
    await user.selectOptions(screen.getByRole("combobox", { name: "Provider" }), "conjur");
    expect(screen.queryByRole("textbox", { name: /Token reference/ })).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Review exact plan" }));
    expect(await screen.findByText("Enter the Conjur server URL as the API endpoint.")).toBeInTheDocument();
    expect(screen.getByText("Enter the Conjur account.")).toBeInTheDocument();
    expect(screen.getByText("Enter the host or user that signs in.")).toBeInTheDocument();
    expect(screen.getByText("Enter the API key reference.")).toBeInTheDocument();
    expect(apiMock.createDiscoverySource).not.toHaveBeenCalled();

    await user.type(screen.getByRole("textbox", { name: /API endpoint/ }), "https://conjur.example.test");
    await user.type(screen.getByRole("textbox", { name: /Conjur account/ }), "prod");
    await user.type(screen.getByRole("textbox", { name: /^Login/ }), "host/apps/discovery");
    await user.type(screen.getByRole("textbox", { name: /API key reference/ }), "env:CONJUR_API_KEY");
    await user.type(screen.getByRole("textbox", { name: /Policy path/ }), "apps");
    await user.click(screen.getByRole("button", { name: "Review exact plan" }));
    await user.click(await screen.findByRole("button", { name: "Save source" }));
    await waitFor(() =>
      expect(apiMock.createDiscoverySource).toHaveBeenCalledWith(
        expect.objectContaining({
          kind: "secret_store",
          config: {
            providers: [
              {
                provider: "conjur",
                endpoint: "https://conjur.example.test",
                account: "prod",
                login: "host/apps/discovery",
                api_key_ref: "env:CONJUR_API_KEY",
                path_prefix: "apps",
              },
            ],
          },
        }),
      ),
    );
  });

  it("asks Infisical for one sign-in and Bitwarden for its access token (OD-13)", async () => {
    const user = userEvent.setup();
    renderSetup();

    await screen.findByText("What this source does");
    await user.selectOptions(screen.getByRole("combobox", { name: "What should trstctl inspect?" }), "secret_store");
    await user.type(screen.getByRole("textbox", { name: "Source name" }), "Infisical secrets");
    await user.selectOptions(screen.getByRole("combobox", { name: "Provider" }), "bitwarden-secrets-manager");
    expect(screen.getByRole("textbox", { name: /Token reference/ })).toBeInTheDocument();
    expect(screen.getByRole("textbox", { name: /Identity endpoint/ })).toBeInTheDocument();
    expect(screen.getByText(/carries the key that decrypts secret names here/)).toBeInTheDocument();
    await user.selectOptions(screen.getByRole("combobox", { name: "Provider" }), "infisical");
    await user.click(screen.getByRole("button", { name: "Review exact plan" }));
    expect(await screen.findByText("Enter the Universal Auth client ID and client secret reference, or a token reference.")).toBeInTheDocument();
    await user.type(screen.getByRole("textbox", { name: /Universal Auth client ID/ }), "ua-client");
    await user.type(screen.getByRole("textbox", { name: /Client secret reference/ }), "env:INFISICAL_SECRET");
    await user.type(screen.getByRole("textbox", { name: /Environment slugs/ }), "dev, prod");
    await user.click(screen.getByRole("button", { name: "Review exact plan" }));
    expect(await screen.findByText("Environments belong to a project; enter the project ID.")).toBeInTheDocument();
    await user.type(screen.getByRole("textbox", { name: /Project ID/ }), "p-1");
    await user.click(screen.getByRole("button", { name: "Review exact plan" }));
    await user.click(await screen.findByRole("button", { name: "Save source" }));
    await waitFor(() =>
      expect(apiMock.createDiscoverySource).toHaveBeenCalledWith(
        expect.objectContaining({
          config: {
            providers: [
              { provider: "infisical", client_id: "ua-client", client_secret_ref: "env:INFISICAL_SECRET", project: "p-1", environments: ["dev", "prod"] },
            ],
          },
        }),
      ),
    );
  });

  it("configures 1Password Connect vaults and Doppler configs (OD-14)", async () => {
    const user = userEvent.setup();
    renderSetup();

    await screen.findByText("What this source does");
    await user.selectOptions(screen.getByRole("combobox", { name: "What should trstctl inspect?" }), "secret_store");
    await user.type(screen.getByRole("textbox", { name: "Source name" }), "Password manager");
    await user.selectOptions(screen.getByRole("combobox", { name: "Provider" }), "doppler");
    await user.type(screen.getByRole("textbox", { name: /Token reference/ }), "env:STORE_TOKEN");
    await user.type(screen.getByRole("textbox", { name: /^Configs/ }), "prd");
    await user.click(screen.getByRole("button", { name: "Review exact plan" }));
    expect(await screen.findByText("Configs belong to a project; enter the Doppler project.")).toBeInTheDocument();

    await user.selectOptions(screen.getByRole("combobox", { name: "Provider" }), "1password-connect");
    await user.click(screen.getByRole("button", { name: "Review exact plan" }));
    expect(await screen.findByText("Enter the Connect server URL as the API endpoint.")).toBeInTheDocument();
    await user.type(screen.getByRole("textbox", { name: /API endpoint/ }), "https://connect.example.test");
    await user.type(screen.getByRole("textbox", { name: /^Vaults/ }), "Payments, Infra");
    await user.click(screen.getByRole("button", { name: "Review exact plan" }));
    await user.click(await screen.findByRole("button", { name: "Save source" }));
    await waitFor(() =>
      expect(apiMock.createDiscoverySource).toHaveBeenCalledWith(
        expect.objectContaining({
          config: {
            providers: [
              { provider: "1password-connect", endpoint: "https://connect.example.test", token_ref: "env:STORE_TOKEN", vaults: ["Payments", "Infra"] },
            ],
          },
        }),
      ),
    );
  });

  it("rejects oversized and invalid port ranges before review", () => {
    expect(() => parsePorts("0")).toThrow(/inside 1–65535/);
    expect(() => parsePorts("1000-1400")).toThrow(/at most 256 ports/);
    expect(parsePorts("443,443,8443-8444")).toEqual([443, 8443, 8444]);
  });

  it("shows the server's exact plan rejection instead of a bare HTTP status", async () => {
    const user = userEvent.setup();
    apiMock.discoveryCoverage.mockResolvedValue({
      ...emptyCoverage,
      segments: [{ name: "production-edge", ranges: ["api.example.test"], status: "never", staleness_hours: 168 }],
    });
    apiMock.previewDiscoveryPlan.mockRejectedValue(
      new ApiError(400, JSON.stringify({ title: "Invalid discovery plan", detail: "Target api.example.test:8443 is outside the declared safety fence." })),
    );
    renderSetup();

    await screen.findByText("What this source does");
    await user.type(screen.getByRole("textbox", { name: "Source name" }), "Production TLS");
    await user.type(screen.getByRole("textbox", { name: "Authorized scope" }), "production-edge");
    await user.type(screen.getByRole("textbox", { name: /Hosts, IPs/ }), "api.example.test");
    await user.click(screen.getByRole("button", { name: "Review exact plan" }));

    expect(await screen.findByRole("alert")).toHaveTextContent("outside the declared safety fence");
    expect(screen.queryByText("request failed (400)")).not.toBeInTheDocument();
    expect(apiMock.createDiscoverySegment).not.toHaveBeenCalled();
  });

  it("fails the parity oracle when the server adds a field the console cannot configure", () => {
    const broken = structuredClone(catalog.items);
    broken[0].configuration.push({
      path: "new_server_only_boundary",
      label: "New boundary",
      type: "string",
      required: false,
      description: "Deliberately unsupported field.",
    });

    expect(sourceWizardContractProblems(broken)).toContain("network: unsupported served field new_server_only_boundary");
    expect(sourceWizardContractProblems(broken.filter((item) => item.kind !== "ssh"))).toContain("ssh: typed source-wizard capability is absent");
  });

  it("matches the reviewed server capability golden instead of a UI-only fixture", () => {
    const path = resolve(process.cwd(), "../internal/discovery/sourcecatalog/testdata/catalog.golden.json");
    const served = JSON.parse(readFileSync(path, "utf8")) as DiscoveryCapabilityCatalog;

    expect(sourceWizardContractProblems(served.items)).toEqual([]);
    expect(served.items.find((item) => item.kind === "agent")).toMatchObject({
      route: "/agents",
      setup_surface: "contextual",
    });
  });
});
