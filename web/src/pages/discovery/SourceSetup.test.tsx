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
    capability("ssh"),
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
  });
});
