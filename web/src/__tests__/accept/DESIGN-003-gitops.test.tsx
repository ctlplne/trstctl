import { beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { Integrate } from "@/pages/Integrate";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    profiles: vi.fn(),
    discoverySources: vi.fn(),
    notificationRoutingPolicies: vi.fn(),
    policyDryRun: vi.fn(),
  },
}));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...apiMock } };
});

function renderIntegrate() {
  return render(
    <MemoryRouter>
      <Integrate />
    </MemoryRouter>,
  );
}

describe("DESIGN-003 GitOps workflow", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    for (const mock of Object.values(apiMock)) mock.mockReset();
    apiMock.profiles.mockResolvedValue([
      {
        id: "profile-1",
        name: "server-tls",
        version: 3,
        active: true,
        spec: { ttl: "24h", key_algorithm: "ecdsa_p256", usages: ["server_auth"] },
      },
    ]);
    apiMock.discoverySources.mockResolvedValue({
      items: [
        {
          id: "source-1",
          tenant_id: "tenant-1",
          name: "edge-network",
          kind: "network",
          config: { targets: ["edge.example.test:443"] },
          created_at: "2026-06-26T10:00:00Z",
          updated_at: "2026-06-26T10:00:00Z",
        },
      ],
    });
    apiMock.notificationRoutingPolicies.mockResolvedValue({
      items: [
        {
          id: "policy-1",
          tenant_id: "tenant-1",
          name: "Expiry escalation",
          channels_by_severity: { critical: ["slack", "webhook"], warning: ["slack"] },
          default_channels: ["webhook"],
          owner_ref: "team/platform",
          digest_interval_seconds: 43200,
          digest_timezone: "UTC",
          digest_preview: { interval_seconds: 43200, timezone: "UTC", next_run_at: "2026-06-27T10:00:00Z" },
          created_at: "2026-06-26T10:00:00Z",
          updated_at: "2026-06-26T10:00:00Z",
        },
      ],
    });
    apiMock.policyDryRun.mockResolvedValue({
      allow: true,
      deny: false,
      valid: true,
      kind: "abac",
      package: "trstctl.gitops",
      query: "data.trstctl.gitops.allow",
      module_sha256: "sha256-gitops",
      audit_event: "policy.dry_run.evaluated",
      idempotency_key: "idem-gitops",
      input_summary: { action: "gitops.validate", actor: "operator@example.test", subject: "server-tls", tenant_id: "tenant-1" },
      trace: [{ op: "eval", query_id: 1, message: "declaration accepted" }],
    });
  });

  it("generates, validates, exports, and drift-checks served GitOps declarations", async () => {
    const user = userEvent.setup();
    renderIntegrate();

    await user.click(screen.getByText("GitOps declarations and drift", { exact: true }));
    expect(await screen.findByRole("heading", { name: "GitOps workflow" })).toBeInTheDocument();
    await waitFor(() => expect(apiMock.profiles).toHaveBeenCalledTimes(1));
    expect(apiMock.discoverySources).toHaveBeenCalledWith({ limit: 50 });
    expect(apiMock.notificationRoutingPolicies).toHaveBeenCalledTimes(1);

    const manifest = screen.getByLabelText("Declarative manifest") as HTMLTextAreaElement;
    expect(manifest.value).toContain('"kind": "TrstctlProfile"');
    expect(manifest.value).toContain('"name": "server-tls"');

    await user.selectOptions(screen.getByLabelText("Manifest type"), "discovery-source");
    expect((screen.getByLabelText("Declarative manifest") as HTMLTextAreaElement).value).toContain('"kind": "TrstctlDiscoverySource"');
    expect((screen.getByLabelText("Declarative manifest") as HTMLTextAreaElement).value).toContain('"name": "edge-network"');

    await user.selectOptions(screen.getByLabelText("Manifest type"), "routing-policy");
    expect((screen.getByLabelText("Declarative manifest") as HTMLTextAreaElement).value).toContain('"kind": "TrstctlNotificationRoutingPolicy"');
    expect((screen.getByLabelText("Declarative manifest") as HTMLTextAreaElement).value).toContain('"default_channels"');

    await user.selectOptions(screen.getByLabelText("Manifest type"), "install-values");
    expect((screen.getByLabelText("Declarative manifest") as HTMLTextAreaElement).value).toContain('"chart": "deploy/helm/trstctl"');
    expect((screen.getByLabelText("Declarative manifest") as HTMLTextAreaElement).value).toContain('"postgres"');

    await user.selectOptions(screen.getByLabelText("Manifest type"), "profile");
    fireEvent.change(manifest, {
      target: {
        value: JSON.stringify(
          {
            apiVersion: "trstctl.com/v1",
            kind: "TrstctlProfile",
            metadata: { name: "server-tls" },
            spec: { version: 2, active: true, spec: { ttl: "12h", key_algorithm: "ecdsa_p256", usages: ["server_auth"] } },
          },
          null,
          2,
        ),
      },
    });

    const driftTable = screen.getByRole("table", { name: "GitOps drift comparison" });
    expect(within(driftTable).getByRole("row", { name: /spec.version 3 2 Drift/i })).toBeInTheDocument();
    expect(within(driftTable).getByRole("row", { name: /spec\.spec\.ttl 24h 12h Drift/i })).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Validate declaration" }));
    await waitFor(() => expect(apiMock.policyDryRun).toHaveBeenCalled());
    expect(apiMock.policyDryRun).toHaveBeenCalledWith(
      expect.objectContaining({
        kind: "abac",
        input: expect.objectContaining({
          action: "gitops.validate",
          subject: "server-tls",
          declaration_kind: "TrstctlProfile",
        }),
      }),
    );
    expect(await screen.findByText("policy.dry_run.evaluated")).toBeInTheDocument();
    expect(screen.getByText("sha256-gitops")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Export declaration" })).toHaveAttribute("download", "trstctl-gitops-profile.json");
    expect(screen.getByRole("link", { name: "Open in API explorer" })).toHaveAttribute("href", "/integrate/api?operation=dryRunPolicy");
  });
});
