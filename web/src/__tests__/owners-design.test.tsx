import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
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
  },
}));

vi.mock("@/lib/bootstrapApi", async (original) => {
  const actual = await original<typeof import("@/lib/bootstrapApi")>();
  return { ...actual, bootstrapApi: apiMock };
});

vi.mock("@/lib/api", async (original) => {
  const actual = await original<typeof import("@/lib/api")>();
  return { ...actual, api: apiMock };
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

describe("route 029 decision-first ownership design", () => {
  beforeEach(() => {
    for (const mock of Object.values(apiMock)) mock.mockReset();
    apiMock.authMethods.mockResolvedValue({ oidc: true, saml: false, ldap: false });
    apiMock.me.mockResolvedValue({ permissions: ["*"], subject: "operator-29", tenant_id: "tenant-29" });
    apiMock.owners.mockResolvedValue([
      {
        id: "owner-platform",
        name: "Platform team",
        kind: "team",
        application_id: "APP-29",
        environment: "production",
        ownership_complete: true,
        ownership_attested: true,
        ownership_current: true,
      },
    ]);
    apiMock.ownershipAttribution.mockResolvedValue({
      generated_at: "2026-08-21T08:00:00Z",
      summary: { total: 2, attributed: 1, orphaned: 1, team_owner: 1 },
      coverage: ["team_owner", "orphaned"],
      items: [
        {
          id: "identity/owned",
          tenant_id: "tenant-29",
          kind: "api_key",
          source: "identity",
          display_name: "release key",
          owner: { id: "owner-platform", tenant_id: "tenant-29", kind: "team", name: "Platform team" },
          attribution_status: "attributed",
          attribution_source: "owner_id",
          attribution_evidence: ["owner_id:owner-platform"],
          created_at: "2026-08-21T08:00:00Z",
        },
        {
          id: "finding/unowned",
          tenant_id: "tenant-29",
          kind: "token",
          source: "discovery_finding",
          display_name: "unowned deployer token",
          attribution_status: "orphaned",
          attribution_source: "unattributed",
          attribution_evidence: [],
          created_at: "2026-08-21T08:00:00Z",
        },
      ],
    });
    apiMock.unownedIdentities.mockResolvedValue({
      counts: { no_owner: 1, owner_missing_application_model: 0, ownership_never_attested: 0, ownership_attestation_stale: 0 },
      items: [{ identity_id: "unowned", name: "unowned deployer token", reason: "no_owner", detail: "No owner is assigned." }],
      guidance: "Assign a durable owner.",
    });
  });

  it("answers accountability before revealing owner machinery", async () => {
    const user = userEvent.setup();
    renderOwners();

    expect(await screen.findByRole("heading", { level: 1, name: "Ownership" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /^Ownership$/ })).toHaveAttribute("href", "/owners");
    expect(screen.getByText("Which team is accountable for every identity and credential.", { exact: true })).toBeInTheDocument();
    expect(await screen.findByRole("heading", { level: 2, name: "1 asset needs accountable ownership" })).toBeInTheDocument();
    expect(screen.getByRole("region", { name: "Accountability hierarchy" })).toHaveTextContent("Platform team");
    expect(screen.getByRole("table", { name: "Ownership action queue" })).toHaveTextContent("unowned deployer token");

    const actions = screen.getByTestId("page-depth-operate");
    expect(within(actions).getAllByRole("button")).toHaveLength(1);
    const assign = within(actions).getByRole("button", { name: /^Add owner$/ });
    expect(screen.queryByRole("searchbox", { name: "Search owners" })).not.toBeInTheDocument();

    const disclosures = [
      "Owner records, inheritance, and attestations",
      "Coverage gaps and temporary exceptions",
      "Sources, disagreements, and review history",
    ].map((title) => screen.getByText(title, { exact: true }).closest("details"));
    expect(disclosures.every((details) => details && !details.hasAttribute("open"))).toBe(true);

    await user.click(assign);
    const assignDialog = screen.getByRole("dialog");
    expect(within(assignDialog).getByRole("heading", { level: 2, name: "Add owner" })).toBeInTheDocument();
    expect(assignDialog).toHaveClass("max-h-[calc(100dvh-2rem)]", "overflow-y-auto", "overscroll-contain");
    expect(assignDialog).not.toHaveClass("motion-safe:animate-panel-in");
    expect(screen.getByText(/Create the accountable owner record first/, { exact: false })).toBeInTheDocument();
    expect(screen.getByLabelText("Name")).toHaveFocus();
    await user.click(screen.getByRole("button", { name: "Cancel" }));

    await user.click(screen.getByText("Owner records, inheritance, and attestations", { exact: true }));
    expect(await screen.findByRole("searchbox", { name: "Search owners" })).toBeVisible();
    expect(screen.getByRole("table", { name: "Credential owners" })).toHaveTextContent("Platform team");

    await user.click(screen.getByText("Sources, disagreements, and review history", { exact: true }));
    expect(await screen.findByRole("table", { name: "NHI ownership attribution" })).toHaveTextContent("unowned deployer token");
    expect(screen.getByText(/Human attestation is never overwritten by an import/, { exact: false })).toBeInTheDocument();
  });

  it("attests a new owner as part of creating it, so deployments are not refused later", async () => {
    const user = userEvent.setup();
    const created = {
      id: "owner-new",
      name: "Partner Lab Web Team",
      kind: "team",
      ownership_complete: true,
      ownership_attested: false,
      ownership_current: false,
    };
    apiMock.createOwner.mockResolvedValue(created);
    apiMock.attestOwner.mockResolvedValue({ ...created, ownership_attested: true, ownership_current: true });
    renderOwners();
    await screen.findByRole("heading", { level: 1, name: "Ownership" });

    await user.click(screen.getByRole("button", { name: /^Add owner$/ }));
    const dialog = screen.getByRole("dialog");
    expect(within(dialog).getByRole("checkbox", { name: /I attest this ownership record is current/ })).toBeChecked();
    await user.type(within(dialog).getByLabelText("Name"), "Partner Lab Web Team");
    await user.click(within(dialog).getByRole("button", { name: "Create owner" }));

    await waitFor(() => expect(apiMock.attestOwner).toHaveBeenCalledWith("owner-new"));
    expect(apiMock.createOwner).toHaveBeenCalledTimes(1);
    expect(apiMock.createOwner.mock.invocationCallOrder[0]).toBeLessThan(apiMock.attestOwner.mock.invocationCallOrder[0]);
  });

  it("leaves attestation to a later human only when the person opts out", async () => {
    const user = userEvent.setup();
    apiMock.createOwner.mockResolvedValue({
      id: "owner-later",
      name: "Later team",
      kind: "team",
      ownership_complete: false,
      ownership_attested: false,
      ownership_current: false,
    });
    renderOwners();
    await screen.findByRole("heading", { level: 1, name: "Ownership" });

    await user.click(screen.getByRole("button", { name: /^Add owner$/ }));
    const dialog = screen.getByRole("dialog");
    await user.click(within(dialog).getByRole("checkbox", { name: /I attest this ownership record is current/ }));
    await user.type(within(dialog).getByLabelText("Name"), "Later team");
    await user.click(within(dialog).getByRole("button", { name: "Create owner" }));

    await waitFor(() => expect(apiMock.createOwner).toHaveBeenCalledTimes(1));
    expect(await screen.findByText("Owner created", { exact: true })).toBeInTheDocument();
    expect(apiMock.attestOwner).not.toHaveBeenCalled();
  });

  it("keeps the exact expert evidence named but closed on first view", async () => {
    const user = userEvent.setup();
    renderOwners();
    await screen.findByRole("heading", { level: 1, name: "Ownership" });

    const technical = screen.getByTestId("page-depth-prove");
    expect(technical).not.toHaveAttribute("open");
    await user.click(within(technical).getByText("Show exact evidence", { exact: true }));
    expect(technical).toHaveTextContent("Rules, inheritance, exceptions, review history.");
  });

  it("does not turn an empty inventory into a success claim", async () => {
    apiMock.owners.mockResolvedValue([]);
    apiMock.ownershipAttribution.mockResolvedValue({
      generated_at: "2026-08-21T08:00:00Z",
      summary: { total: 0, attributed: 0, orphaned: 0 },
      coverage: [],
      items: [],
    });
    renderOwners();

    expect(await screen.findByRole("heading", { level: 2, name: "No identities or credentials are known yet" })).toBeInTheDocument();
    expect(screen.queryByText("Every known identity and credential has an owner", { exact: true })).not.toBeInTheDocument();
  });
});
