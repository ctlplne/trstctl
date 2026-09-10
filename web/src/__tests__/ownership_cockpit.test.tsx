import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { axe } from "vitest-axe";
import { ThemeProvider } from "@/components/ThemeProvider";
import { AuthProvider } from "@/auth/AuthProvider";
import { AppRoutes } from "@/App";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    me: vi.fn(),
    authMethods: vi.fn(),
    owners: vi.fn(),
    ownershipAttribution: vi.fn(),
    unownedIdentities: vi.fn(),
    createOwner: vi.fn(),
    updateOwner: vi.fn(),
    deleteOwner: vi.fn(),
    attestOwner: vi.fn(),
    assignOwnership: vi.fn(),
  },
}));

vi.mock("@/lib/bootstrapApi", async (original) => {
  const actual = await original<typeof import("@/lib/bootstrapApi")>();
  return { ...actual, bootstrapApi: { ...actual.bootstrapApi, ...apiMock } };
});

vi.mock("@/lib/api", async (original) => {
  const actual = await original<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...apiMock } };
});

function renderOwners() {
  return render(
    <ThemeProvider>
      <AuthProvider>
        <MemoryRouter initialEntries={["/owners"]}>
          <AppRoutes />
        </MemoryRouter>
      </AuthProvider>
    </ThemeProvider>,
  );
}

describe("ownership operations cockpit", () => {
  beforeEach(() => {
    for (const mock of Object.values(apiMock)) mock.mockReset();
    apiMock.authMethods.mockResolvedValue({ oidc: true, saml: false, ldap: false });
    apiMock.me.mockResolvedValue({ permissions: ["*"], subject: "operator-ownership", tenant_id: "tenant-1" });
    apiMock.owners.mockResolvedValue([
      {
        id: "owner-platform",
        tenant_id: "tenant-1",
        kind: "team",
        name: "Platform Trust",
        email: "platform@example.test",
        application_id: "APP-PLATFORM",
        service: "Trust platform",
        business_unit: "Engineering",
        environment: "production",
        escalation_chain: ["platform-oncall@example.test", "security@example.test"],
        ownership_attested: true,
        ownership_complete: true,
        ownership_current: true,
        ownership_attestation_due_at: "2026-11-20T12:00:00Z",
        ownership_source: "service-now",
        ownership_source_observed_at: "2026-08-24T11:30:00Z",
      },
      {
        id: "owner-mobile",
        tenant_id: "tenant-1",
        kind: "service",
        name: "Mobile MDM",
        application_id: "APP-MDM",
        service: "Device enrollment",
        business_unit: "Product",
        environment: "production",
        escalation_chain: [],
        ownership_attested: false,
        ownership_complete: true,
        ownership_current: false,
      },
    ]);
    apiMock.ownershipAttribution.mockResolvedValue({
      generated_at: "2026-08-24T12:00:00Z",
      summary: { total: 5, attributed: 3, orphaned: 2, team: 2, service: 1 },
      coverage: ["team_owner", "service_owner", "orphaned"],
      items: [
        {
          id: "identity/identity-api",
          tenant_id: "tenant-1",
          kind: "certificate",
          source: "identity",
          display_name: "api.prod.example",
          owner: { id: "owner-platform", tenant_id: "tenant-1", kind: "team", name: "Platform Trust", email: "platform@example.test" },
          attribution_status: "attributed",
          attribution_source: "owner_id",
          attribution_evidence: ["owner_id:owner-platform"],
          created_at: "2026-08-24T10:00:00Z",
        },
        {
          id: "certificate/cert-api",
          tenant_id: "tenant-1",
          kind: "certificate",
          source: "certificate_inventory",
          display_name: "CN=api.prod.example",
          owner: { id: "owner-platform", tenant_id: "tenant-1", kind: "team", name: "Platform Trust", email: "platform@example.test" },
          attribution_status: "attributed",
          attribution_source: "owner_id",
          attribution_evidence: ["owner_id:owner-platform"],
          created_at: "2026-08-24T10:00:00Z",
        },
        {
          id: "agent/agent-1",
          tenant_id: "tenant-1",
          kind: "agent",
          source: "agent_fleet",
          display_name: "prod-relay-1",
          owner: { id: "owner-mobile", tenant_id: "tenant-1", kind: "service", name: "Mobile MDM" },
          attribution_status: "attributed",
          attribution_source: "asset_override",
          attribution_evidence: ["ownership.assignment:owner-mobile"],
          created_at: "2026-08-24T10:00:00Z",
        },
        {
          id: "finding/finding-token",
          tenant_id: "tenant-1",
          kind: "token",
          source: "discovery_finding",
          display_name: "unowned deploy token",
          attribution_status: "orphaned",
          attribution_source: "unattributed",
          attribution_evidence: [],
          created_at: "2026-08-24T10:00:00Z",
        },
        {
          id: "identity/identity-worker",
          tenant_id: "tenant-1",
          kind: "workload_identity",
          source: "identity",
          display_name: "payments worker",
          attribution_status: "orphaned",
          attribution_source: "unattributed",
          attribution_evidence: [],
          created_at: "2026-08-24T10:00:00Z",
        },
      ],
    });
    apiMock.unownedIdentities.mockResolvedValue({
      counts: {
        no_owner: 1,
        owner_missing_application_model: 0,
        ownership_never_attested: 1,
        ownership_attestation_stale: 0,
      },
      items: [
        { identity_id: "identity-worker", name: "payments worker", reason: "no_owner", detail: "No owner is assigned." },
        { identity_id: "identity-mobile", name: "mobile issuer", reason: "ownership_never_attested", detail: "Owner review is missing." },
      ],
      guidance: "Assign durable teams and review them on schedule.",
    });
    apiMock.assignOwnership.mockResolvedValue({
      owner_id: "owner-platform",
      assigned: ["finding/finding-token", "identity/identity-worker"],
      assigned_at: "2026-08-24T12:10:00Z",
      assigned_by: "operator-ownership",
    });
  });

  it("shows hierarchy, accountable routes, readiness, and gap work without opening expert disclosures", async () => {
    const view = renderOwners();

    const cockpit = await screen.findByRole("region", { name: "Ownership operations" });
    expect(within(cockpit).getByRole("heading", { level: 2, name: "2 assets need accountable ownership" })).toBeInTheDocument();
    expect(within(cockpit).getByText("5", { selector: "[data-metric='known-assets']" })).toBeInTheDocument();
    expect(within(cockpit).getByText("2", { selector: "[data-metric='owner-gaps']" })).toBeInTheDocument();
    expect(within(cockpit).getByText("1", { selector: "[data-metric='review-gaps']" })).toBeInTheDocument();
    expect(within(cockpit).getByText("1", { selector: "[data-metric='route-gaps']" })).toBeInTheDocument();

    const hierarchy = within(cockpit).getByRole("region", { name: "Accountability hierarchy" });
    expect(within(hierarchy).getByRole("heading", { name: "Engineering" })).toBeInTheDocument();
    expect(within(hierarchy).getByText("Platform Trust")).toBeInTheDocument();
    expect(within(hierarchy).getByText("2 affected assets")).toBeInTheDocument();
    expect(within(hierarchy).getByText("platform@example.test → platform-oncall@example.test → security@example.test")).toBeInTheDocument();
    expect(within(hierarchy).getByText(/Current until Nov 20, 2026/)).toBeInTheDocument();
    expect(within(hierarchy).getByRole("heading", { name: "Product" })).toBeInTheDocument();
    expect(within(hierarchy).getByText("No reachable alert route")).toBeInTheDocument();

    const gaps = within(cockpit).getByRole("table", { name: "Ownership action queue" });
    expect(within(gaps).getByRole("row", { name: /unowned deploy token/i })).toHaveTextContent("No effective owner");
    expect(within(gaps).getByRole("row", { name: /payments worker/i })).toHaveTextContent("No owner is assigned");

    expect(screen.getByText("Sources, disagreements, and review history").closest("details")).not.toHaveAttribute("open");
    expect(await axe(view.container)).toHaveNoViolations();
  });

  it("bulk-assigns selected real inventory records with an audit reason", async () => {
    const user = userEvent.setup();
    renderOwners();
    const cockpit = within(await screen.findByRole("region", { name: "Ownership operations" }));
    const queue = cockpit.getByRole("table", { name: "Ownership action queue" });
    await user.click(within(queue).getByRole("checkbox", { name: /select unowned deploy token/i }));
    await user.click(within(queue).getByRole("checkbox", { name: /select payments worker/i }));
    await user.click(cockpit.getByRole("button", { name: "Assign 2 selected assets" }));

    const dialog = screen.getByRole("dialog", { name: "Assign accountable owner" });
    await user.selectOptions(within(dialog).getByLabelText("Accountable owner"), "owner-platform");
    await user.type(within(dialog).getByLabelText("Why is this ownership correct?"), "Platform Trust operates both production assets.");
    await user.click(within(dialog).getByRole("button", { name: "Assign owner" }));

    expect(apiMock.assignOwnership).toHaveBeenCalledWith({
      owner_id: "owner-platform",
      inventory_ids: ["finding/finding-token", "identity/identity-worker"],
      reason: "Platform Trust operates both production assets.",
    });
    expect(await screen.findByText("2 assets now belong to Platform Trust")).toBeInTheDocument();
  });

  it("filters owned inventory and hands an existing asset to another durable owner", async () => {
    const user = userEvent.setup();
    apiMock.assignOwnership.mockResolvedValueOnce({
      owner_id: "owner-mobile",
      assigned: ["identity/identity-api"],
      assigned_at: "2026-08-24T12:15:00Z",
      assigned_by: "operator-ownership",
    });
    renderOwners();
    const cockpit = within(await screen.findByRole("region", { name: "Ownership operations" }));
    await user.selectOptions(cockpit.getByLabelText("Assets shown"), "all");
    await user.selectOptions(cockpit.getByLabelText("Current owner"), "owner-platform");

    const queue = cockpit.getByRole("table", { name: "Ownership action queue" });
    const identitySelection = within(queue).getByRole("checkbox", { name: "Select api.prod.example" });
    expect(identitySelection.closest("tr")).toHaveTextContent("Currently owned by Platform Trust");
    expect(within(queue).queryByText("prod-relay-1")).not.toBeInTheDocument();
    await user.click(identitySelection);
    await user.click(cockpit.getByRole("button", { name: "Change owner for selected asset" }));

    const dialog = screen.getByRole("dialog", { name: "Assign accountable owner" });
    await user.selectOptions(within(dialog).getByLabelText("Accountable owner"), "owner-mobile");
    await user.type(within(dialog).getByLabelText("Why is this ownership correct?"), "Mobile MDM now operates this production identity.");
    await user.click(within(dialog).getByRole("button", { name: "Assign owner" }));

    expect(apiMock.assignOwnership).toHaveBeenCalledWith({
      owner_id: "owner-mobile",
      inventory_ids: ["identity/identity-api"],
      reason: "Mobile MDM now operates this production identity.",
    });
    expect(await screen.findByText("1 asset now belongs to Mobile MDM")).toBeInTheDocument();
  });
});
