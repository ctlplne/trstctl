import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { Identities, graphNodeIdForIdentity } from "@/pages/Identities";
// The real ApiError class (the vi.mock below spreads the real module and only
// replaces `api`), used to simulate a 429 with a Retry-After hint (SURFACE-007).
import { ApiError } from "@/lib/api";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    identities: vi.fn(),
    issuers: vi.fn(),
    owners: vi.fn(),
    getIdentity: vi.fn(),
    issueCertificate: vi.fn(),
    transitionIdentity: vi.fn(),
    decommissionNHI: vi.fn(),
    approveIdentityAction: vi.fn(),
    graphBlastRadius: vi.fn(),
    connectorDeliveries: vi.fn(),
    rotationRuns: vi.fn(),
    bulkRevokeIdentities: vi.fn(),
  },
}));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: apiMock };
});

function renderIdentities() {
  return render(
    <MemoryRouter>
      <Identities />
    </MemoryRouter>,
  );
}

describe("lifecycle actions from the UI", () => {
  beforeEach(() => {
    apiMock.issuers.mockReset().mockResolvedValue([{ id: "iss-1", kind: "x509_ca", name: "LE" }]);
    apiMock.owners.mockReset().mockResolvedValue([{ id: "own-1", kind: "workload", name: "team" }]);
    // Fixtures use `status` — the field the SERVED Identity contract (OpenAPI) carries
    // and that identityState() reads (SURFACE-005: the FE no longer guesses `state`).
    apiMock.issueCertificate.mockReset().mockResolvedValue({ id: "new-1", name: "svc", status: "issued" });
    apiMock.getIdentity.mockReset();
    apiMock.transitionIdentity.mockReset().mockResolvedValue({ id: "x", name: "x", status: "x" });
    apiMock.decommissionNHI.mockReset().mockResolvedValue({
      capability: "CAP-GOV-04",
      coverage: ["departure", "vendor_term", "inactivity", "revoke", "retire"],
      reason: "departure decommission via UI",
      summary: { total_matched: 1, revoked: 1, retired: 0, skipped: 0, failed: 0 },
      items: [
        {
          identity_id: "dep-1",
          name: "payments-api",
          kind: "api_key",
          owner_id: "own-1",
          signal_type: "departure",
          action: "revoked",
          from: "deployed",
          to: "revoked",
        },
      ],
    });
    apiMock.approveIdentityAction.mockReset().mockResolvedValue({ resource: "req-1", action: "issue", approver: "ra", approvals: 1 });
    apiMock.graphBlastRadius.mockReset().mockResolvedValue({
      node: { id: "cert:demo", kind: "credential", name: "demo" },
      affected: [],
      by_kind: {},
    });
    apiMock.connectorDeliveries.mockReset().mockResolvedValue({ items: [] });
    apiMock.rotationRuns.mockReset().mockResolvedValue({ items: [] });
    apiMock.identities.mockReset();
  });

  it("maps served identity data to graph node IDs conservatively", () => {
    expect(
      graphNodeIdForIdentity({
        id: "dep-1",
        name: "tls-api",
        kind: "x509_certificate",
        owner_id: "owner-1",
        status: "deployed",
      }),
    ).toBe("cert:dep-1");
    expect(
      graphNodeIdForIdentity({
        id: "dep-2",
        name: "tls-api",
        kind: "x509_certificate",
        owner_id: "owner-1",
        status: "deployed",
        attributes: { graph_node_id: "credential:dep-2" },
      }),
    ).toBe("credential:dep-2");
    expect(
      graphNodeIdForIdentity({
        id: "api-1",
        name: "api-key",
        kind: "api_key",
        owner_id: "owner-1",
        status: "deployed",
      }),
    ).toBeNull();
  });

  it("offers the state-appropriate action and calls the transition endpoint", async () => {
    apiMock.identities.mockResolvedValue([
      { id: "req-1", name: "requested-svc", status: "requested" },
      { id: "iss-1", name: "issued-svc", status: "issued" },
      { id: "dep-1", name: "deployed-svc", status: "deployed" },
    ]);
    const user = userEvent.setup();
    renderIdentities();

    // A requested identity can be issued.
    const reqRow = (await screen.findByText("requested-svc")).closest("tr")!;
    await user.click(within(reqRow).getByRole("button", { name: /^issue$/i }));
    await waitFor(() => expect(apiMock.transitionIdentity).toHaveBeenCalledWith("req-1", "issued", expect.anything()));

    // An issued identity can be deployed or revoked.
    const issRow = screen.getByText("issued-svc").closest("tr")!;
    await user.click(within(issRow).getByRole("button", { name: /deploy/i }));
    await waitFor(() => expect(apiMock.transitionIdentity).toHaveBeenCalledWith("iss-1", "deployed", expect.anything()));

    // A deployed identity can be renewed.
    const depRow = screen.getByText("deployed-svc").closest("tr")!;
    await user.click(within(depRow).getByRole("button", { name: /renew/i }));
    await waitFor(() => expect(apiMock.transitionIdentity).toHaveBeenCalledWith("dep-1", "renewing", expect.anything()));
  });

  it("renders identities on the shared DataGrid with lifecycle badges and all six kind filters", async () => {
    const fixtures = [
      { id: "x509-1", name: "tls-api", kind: "x509_certificate", owner_id: "owner-x", status: "issued" },
      { id: "ssh-cert-1", name: "ssh-user", kind: "ssh_certificate", owner_id: "owner-sshc", status: "requested" },
      { id: "ssh-key-1", name: "deploy-key", kind: "ssh_key", owner_id: "owner-ssh", status: "deployed" },
      { id: "secret-1", name: "db-password", kind: "secret", owner_id: "owner-sec", status: "revoked" },
      { id: "api-key-1", name: "stripe-token", kind: "api_key", owner_id: "owner-api", status: "retired" },
      { id: "workload-1", name: "payments-worker", kind: "workload_identity", owner_id: "owner-work", status: "renewing" },
    ];
    apiMock.identities.mockResolvedValue(fixtures);
    const user = userEvent.setup();
    renderIdentities();

    const table = await screen.findByRole("table", { name: /credential identities/i });
    expect(table).toBeInTheDocument();
    expect(within(table).getAllByRole("columnheader")).toHaveLength(6);
    expect(within(table).queryByRole("columnheader", { name: "Credential type" })).not.toBeInTheDocument();
    expect(screen.getByText("issued")).toHaveAttribute("data-status-badge", "lifecycle");
    expect(screen.getAllByText("Owner record unavailable").length).toBeGreaterThan(0);

    for (const identity of fixtures) {
      await user.selectOptions(screen.getByLabelText("Credential type"), identity.kind);
      expect(await screen.findByText(identity.name)).toBeInTheDocument();
      for (const other of fixtures.filter((fixture) => fixture.id !== identity.id)) {
        expect(screen.queryByText(other.name)).not.toBeInTheDocument();
      }
    }

    await user.selectOptions(screen.getByLabelText("Credential type"), "all");
    expect(await screen.findByText("tls-api")).toBeInTheDocument();
    expect(screen.getByText("payments-worker")).toBeInTheDocument();
  });

  it("makes the identity journey search-first and translates owner, kind, and delivery internals into operator language", async () => {
    apiMock.owners.mockResolvedValue([
      {
        id: "owner-payments",
        tenant_id: "tenant-1",
        kind: "team",
        name: "Payments API",
        environment: "production",
        escalation_chain: [],
        ownership_attested: true,
        ownership_complete: true,
        ownership_current: true,
      },
    ]);
    apiMock.identities.mockResolvedValue([
      { id: "payments-1", name: "payments-api", kind: "x509_certificate", owner_id: "owner-payments", status: "deployed" },
      { id: "deploy-1", name: "release-deploy", kind: "ssh_key", owner_id: "owner-missing", status: "deployed" },
    ]);
    apiMock.connectorDeliveries.mockResolvedValue({
      items: [
        {
          id: "delivery-1",
          identity_id: "payments-1",
          connector: "api-token",
          target: "github-actions/release",
          status: "failed",
          reason: "plugin_surface_unconfigured",
          fingerprint: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          created_at: "2026-08-20T00:00:00Z",
          updated_at: "2026-08-20T00:00:00Z",
        },
      ],
    });
    const user = userEvent.setup();

    renderIdentities();

    expect(await screen.findByRole("heading", { name: "Machine identities" })).toBeInTheDocument();
    expect(screen.getByText("Which machines and services have identities, and whether they are healthy.")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Find identities" })).toHaveAttribute("href", "#identity-search");
    expect(screen.getByRole("button", { name: "Add identity" })).toBeInTheDocument();

    const paymentsRow = screen.getByText("payments-api").closest("tr")!;
    expect(paymentsRow).toHaveTextContent("TLS certificate");
    expect(paymentsRow).toHaveTextContent("Payments API");
    expect(paymentsRow).toHaveTextContent("Production");
    expect(paymentsRow).toHaveTextContent("Not delivered yet — this connector still needs setup.");
    expect(paymentsRow).not.toHaveTextContent("owner-payments");
    expect(paymentsRow).not.toHaveTextContent("plugin_surface_unconfigured");

    await user.type(screen.getByRole("searchbox", { name: "Find identities" }), "release");
    expect(screen.queryByText("payments-api")).not.toBeInTheDocument();
    const releaseRow = screen.getByText("release-deploy").closest("tr")!;
    expect(within(releaseRow).getByText("SSH key")).toBeInTheDocument();
    expect(within(releaseRow).getByText("Owner record unavailable")).toBeInTheDocument();
  });

  it("loads kind-specific identity details and links owner plus issuer", async () => {
    const details = {
      "x509/1": {
        id: "x509/1",
        name: "tls-api",
        kind: "x509_certificate",
        owner_id: "owner-x",
        issuer_id: "issuer-x",
        status: "issued",
        not_after: "2026-07-01T00:00:00Z",
        attributes: { dns_names: ["api.example.test"] },
      },
      "ssh-key-1": {
        id: "ssh-key-1",
        name: "deploy-key",
        kind: "ssh_key",
        owner_id: "owner-ssh",
        status: "deployed",
        attributes: { fingerprint: "SHA256:abc" },
      },
      "workload-1": {
        id: "workload-1",
        name: "payments-worker",
        kind: "workload_identity",
        owner_id: "owner-workload",
        issuer_id: "issuer-workload",
        status: "requested",
        attributes: { spiffe_id: "spiffe://example.test/payments" },
      },
    };
    apiMock.identities.mockResolvedValue(Object.values(details));
    apiMock.getIdentity.mockImplementation(async (id: keyof typeof details) => details[id]);
    const user = userEvent.setup();
    renderIdentities();

    const x509Row = (await screen.findByText("tls-api")).closest("tr")!;
    await user.click(within(x509Row).getByRole("button", { name: /view details/i }));

    await waitFor(() => expect(apiMock.getIdentity).toHaveBeenCalledWith("x509/1"));
    expect(await screen.findByRole("dialog", { name: "Identity detail" })).toBeInTheDocument();
    expect(await screen.findByText("X.509 certificate identity")).toBeInTheDocument();
    expect(screen.getByText("Not after")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Owner record unavailable" })).toHaveAttribute("href", "/owners?owner=owner-x");
    await user.click(screen.getByText("Show owner ID"));
    expect(screen.getByText("owner-x")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Issuer issuer-x" })).toHaveAttribute("href", "/protocols?issuer=issuer-x");
    expect(screen.getByText(/api.example.test/)).toBeInTheDocument();
    await user.click(within(screen.getByRole("dialog", { name: "Identity detail" })).getByRole("button", { name: "Close" }));

    const sshRow = screen.getByText("deploy-key").closest("tr")!;
    await user.click(within(sshRow).getByRole("button", { name: /view details/i }));
    expect(await screen.findByText("SSH key identity")).toBeInTheDocument();
    expect(screen.getByText("No issuer bound")).toBeInTheDocument();
    expect(screen.getByText(/SHA256:abc/)).toBeInTheDocument();
    await user.click(within(screen.getByRole("dialog", { name: "Identity detail" })).getByRole("button", { name: "Close" }));

    const workloadRow = screen.getByText("payments-worker").closest("tr")!;
    await user.click(within(workloadRow).getByRole("button", { name: /view details/i }));
    expect(await screen.findByRole("heading", { name: "Workload identity" })).toBeInTheDocument();
    expect(screen.getByText(/spiffe:\/\/example.test\/payments/)).toBeInTheDocument();
  });

  it("traps focus in the identity detail drawer and returns focus to the opener", async () => {
    const identity = {
      id: "x509/1",
      name: "tls-api",
      kind: "x509_certificate",
      owner_id: "owner-x",
      issuer_id: "issuer-x",
      status: "issued",
    };
    apiMock.identities.mockResolvedValue([identity]);
    apiMock.getIdentity.mockResolvedValue(identity);
    const user = userEvent.setup();
    renderIdentities();

    const row = (await screen.findByText("tls-api")).closest("tr")!;
    const opener = within(row).getByRole("button", { name: /view details/i });
    await user.click(opener);

    const dialog = await screen.findByRole("dialog", { name: "Identity detail" });
    const close = within(dialog).getByRole("button", { name: "Close" });
    const lastAction = within(dialog).getByRole("button", { name: "Move to revoked" });

    expect(close).toHaveFocus();

    await user.tab({ shift: true });
    expect(lastAction).toHaveFocus();

    await user.tab();
    expect(close).toHaveFocus();

    await user.keyboard("{Escape}");
    expect(screen.queryByRole("dialog", { name: "Identity detail" })).not.toBeInTheDocument();
    expect(opener).toHaveFocus();
  });

  it("renders the per-credential activity timeline disclosure in the identity drawer (FE-022)", async () => {
    const identity = {
      id: "dep-1",
      name: "timeline-svc",
      kind: "x509_certificate",
      owner_id: "owner-1",
      status: "deployed",
    };
    apiMock.identities.mockResolvedValue([identity]);
    apiMock.getIdentity.mockResolvedValue(identity);
    const user = userEvent.setup();
    renderIdentities();

    const row = (await screen.findByText("timeline-svc")).closest("tr")!;
    await user.click(within(row).getByRole("button", { name: /view details/i }));

    const dialog = await screen.findByRole("dialog", { name: "Identity detail" });
    expect(within(dialog).getByText("Credential activity timeline")).toBeInTheDocument();
    expect(within(dialog).getByText(/projected connector and rotation evidence/i)).toBeInTheDocument();
    for (const state of ["Lifecycle accepted", "Connector delivery", "Rotation run", "Rollback evidence"]) {
      expect(within(dialog).getByText(state)).toBeInTheDocument();
    }
    expect(within(dialog).getByText("no connector delivery receipt yet")).toBeInTheDocument();
    expect(within(dialog).getByText("no lifecycle rotation run yet")).toBeInTheDocument();
    expect(apiMock.connectorDeliveries).toHaveBeenCalledWith({ limit: 50 });
    expect(apiMock.rotationRuns).toHaveBeenCalledWith({ limit: 50 });
  });

  it("disables invalid state-machine targets and sends the captured transition reason", async () => {
    const identity = { id: "req-1", name: "request-state-machine", kind: "x509_certificate", owner_id: "owner-1", status: "requested" };
    apiMock.identities.mockResolvedValue([identity]);
    apiMock.getIdentity.mockResolvedValue(identity);
    const user = userEvent.setup();
    renderIdentities();

    const row = (await screen.findByText("request-state-machine")).closest("tr")!;
    await user.click(within(row).getByRole("button", { name: /view details/i }));

    expect(await screen.findByText("Lifecycle state machine")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Move to issued" })).toBeEnabled();
    expect(screen.getByRole("button", { name: "Move to deployed" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Move to retired" })).toBeDisabled();

    await user.type(screen.getByLabelText("Transition reason"), "approved in CAB-1234");
    await user.click(screen.getByRole("button", { name: "Move to issued" }));

    await waitFor(() => expect(apiMock.transitionIdentity).toHaveBeenCalledWith("req-1", "issued", "approved in CAB-1234"));
  });

  it("shows revoked and retired terminal handling in the state machine", async () => {
    const revoked = { id: "rev-1", name: "revoked-svc", kind: "api_key", owner_id: "owner-r", status: "revoked" };
    const retired = { id: "ret-1", name: "retired-svc", kind: "secret", owner_id: "owner-t", status: "retired" };
    apiMock.identities.mockResolvedValue([revoked, retired]);
    apiMock.getIdentity.mockImplementation(async (id: string) => (id === "rev-1" ? revoked : retired));
    const user = userEvent.setup();
    renderIdentities();

    const revokedRow = (await screen.findByText("revoked-svc")).closest("tr")!;
    await user.click(within(revokedRow).getByRole("button", { name: /view details/i }));
    expect(await screen.findByText(/Terminal trust state/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Move to issued" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Move to retired" })).toBeEnabled();
    await user.click(within(screen.getByRole("dialog", { name: "Identity detail" })).getByRole("button", { name: "Close" }));

    const retiredRow = screen.getByText("retired-svc").closest("tr")!;
    await user.click(within(retiredRow).getByRole("button", { name: /view details/i }));
    expect(await screen.findByText(/Terminal state: retired identities/i)).toBeInTheDocument();
    for (const target of ["issued", "deployed", "renewing", "revoked", "retired"]) {
      expect(screen.getByRole("button", { name: `Move to ${target}` })).toBeDisabled();
    }
  });

  it("revokes an identity only after the user confirms (SURFACE-007)", async () => {
    apiMock.identities.mockResolvedValue([{ id: "dep-9", name: "to-revoke", status: "deployed" }]);
    const user = userEvent.setup();
    renderIdentities();

    const row = (await screen.findByText("to-revoke")).closest("tr")!;
    // Clicking Revoke must NOT immediately call the destructive transition — it opens
    // a confirmation dialog that names the credential.
    await user.click(within(row).getByRole("button", { name: /^revoke$/i }));
    expect(apiMock.transitionIdentity).not.toHaveBeenCalled();
    const dialog = await screen.findByRole("alertdialog");
    // The dialog names the credential (it appears in both the heading and the body).
    expect(within(dialog).getAllByText(/to-revoke/).length).toBeGreaterThan(0);
    expect(within(dialog).getByRole("heading")).toHaveTextContent(/revoke.*to-revoke/i);
    expect(within(dialog).getByRole("button", { name: /yes, revoke/i })).toBeDisabled();
    expect(within(dialog).getByLabelText(/type credential name/i)).toHaveFocus();

    await user.tab({ shift: true });
    expect(within(dialog).getByRole("button", { name: /cancel/i })).toHaveFocus();

    await user.tab();
    expect(within(dialog).getByLabelText(/type credential name/i)).toHaveFocus();

    // Confirming requires the credential name and sends the operator reason.
    await user.type(within(dialog).getByLabelText(/type credential name/i), "to-revoke");
    const reason = within(dialog).getByLabelText(/revocation reason/i);
    await user.clear(reason);
    await user.type(reason, "key compromise CAB-9001");
    await user.click(within(dialog).getByRole("button", { name: /yes, revoke/i }));
    await waitFor(() => expect(apiMock.transitionIdentity).toHaveBeenCalledWith("dep-9", "revoked", "key compromise CAB-9001"));
  });

  it("shows served blast-radius impact before destructive confirmation (FE-083)", async () => {
    apiMock.identities.mockResolvedValue([{ id: "dep-9", name: "to-revoke", kind: "x509_certificate", owner_id: "owner-1", status: "deployed" }]);
    apiMock.graphBlastRadius.mockResolvedValue({
      node: { id: "cert:dep-9", kind: "credential", name: "to-revoke certificate" },
      affected: [
        { id: "workload:api", kind: "workload", name: "payments-api" },
        { id: "workload:worker", kind: "workload", name: "payments-worker" },
        { id: "resource:db", kind: "resource", name: "payments-db" },
      ],
      by_kind: { workload: 2, resource: 1 },
    });
    const user = userEvent.setup();
    renderIdentities();

    const row = (await screen.findByText("to-revoke")).closest("tr")!;
    await user.click(within(row).getByRole("button", { name: /^revoke$/i }));

    await waitFor(() => expect(apiMock.graphBlastRadius).toHaveBeenCalledWith("cert:dep-9"));
    const dialog = await screen.findByRole("alertdialog");
    expect(await within(dialog).findByText("Blast-radius impact")).toBeInTheDocument();
    expect(within(dialog).getByText(/cert:dep-9/)).toBeInTheDocument();
    expect(within(dialog).getByText(/3 downstream affected nodes/i)).toBeInTheDocument();
    expect(within(dialog).getByText("workload")).toBeInTheDocument();
    expect(within(dialog).getByText("2")).toBeInTheDocument();
    expect(within(dialog).getByText("resource")).toBeInTheDocument();
    expect(within(dialog).getByText("1")).toBeInTheDocument();
  });

  it("does not invent blast-radius impact when no graph node mapping exists (FE-083)", async () => {
    apiMock.identities.mockResolvedValue([{ id: "api-9", name: "api-key", kind: "api_key", owner_id: "owner-1", status: "deployed" }]);
    const user = userEvent.setup();
    renderIdentities();

    const row = (await screen.findByText("api-key")).closest("tr")!;
    await user.click(within(row).getByRole("button", { name: /^revoke$/i }));

    expect(apiMock.graphBlastRadius).not.toHaveBeenCalled();
    const dialog = await screen.findByRole("alertdialog");
    expect(within(dialog).getByText(/no graph node mapping/i)).toBeInTheDocument();
  });

  it("degrades blast-radius impact when the graph request fails (FE-083)", async () => {
    apiMock.identities.mockResolvedValue([{ id: "dep-404", name: "missing-graph-node", kind: "x509_certificate", owner_id: "owner-1", status: "deployed" }]);
    apiMock.graphBlastRadius.mockRejectedValue(new ApiError(404, JSON.stringify({ detail: "graph node not found" })));
    const user = userEvent.setup();
    renderIdentities();

    const row = (await screen.findByText("missing-graph-node")).closest("tr")!;
    await user.click(within(row).getByRole("button", { name: /^revoke$/i }));

    await waitFor(() => expect(apiMock.graphBlastRadius).toHaveBeenCalledWith("cert:dep-404"));
    const dialog = await screen.findByRole("alertdialog");
    expect(await within(dialog).findByText(/Blast-radius impact unavailable: graph node not found/i)).toBeInTheDocument();
  });

  it("cancelling the confirmation does not revoke (SURFACE-007)", async () => {
    apiMock.identities.mockResolvedValue([{ id: "dep-9", name: "keep-me", status: "deployed" }]);
    const user = userEvent.setup();
    renderIdentities();

    const row = (await screen.findByText("keep-me")).closest("tr")!;
    const opener = within(row).getByRole("button", { name: /^revoke$/i });
    await user.click(opener);
    const dialog = await screen.findByRole("alertdialog");
    expect(within(dialog).getByLabelText(/type credential name/i)).toHaveFocus();
    await user.keyboard("{Escape}");
    expect(apiMock.transitionIdentity).not.toHaveBeenCalled();
    expect(screen.queryByRole("alertdialog")).not.toBeInTheDocument();
    expect(opener).toHaveFocus();
  });

  it("bulk revokes selected identities with one transactional request and a server-reported summary", async () => {
    apiMock.identities.mockResolvedValue([
      { id: "dep-1", name: "bulk-ok", kind: "x509_certificate", owner_id: "owner-1", status: "deployed" },
      { id: "dep-2", name: "bulk-fail", kind: "x509_certificate", owner_id: "owner-2", status: "deployed" },
      { id: "req-1", name: "not-selected", kind: "x509_certificate", owner_id: "owner-3", status: "requested" },
    ]);
    // One transactional call; the server reports per-item outcomes (no client fan-out).
    apiMock.bulkRevokeIdentities.mockResolvedValue({
      total_matched: 2,
      total_revoked: 1,
      total_skipped: 0,
      total_failed: 1,
      items: [
        { id: "dep-1", status: "revoked" },
        { id: "dep-2", status: "failed", error: "connector queue unavailable" },
      ],
    });
    const user = userEvent.setup();
    renderIdentities();

    await user.click(await screen.findByLabelText("Select bulk-ok"));
    await user.click(screen.getByLabelText("Select bulk-fail"));
    expect(screen.getByText("2 selected")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Bulk revoke selected" }));

    const dialog = await screen.findByRole("alertdialog", { name: /Revoke 2 selected identities/i });
    expect(within(dialog).getByText(/single bulk revocation request/i)).toBeInTheDocument();
    expect(within(dialog).getByRole("button", { name: "Confirm bulk revoke" })).toHaveFocus();

    // Pick an explicit RFC 5280 reason before confirming.
    await user.selectOptions(within(dialog).getByLabelText("Revocation reason"), "keyCompromise");
    await user.click(within(dialog).getByRole("button", { name: "Confirm bulk revoke" }));

    await waitFor(() => expect(apiMock.bulkRevokeIdentities).toHaveBeenCalledTimes(1));
    expect(apiMock.bulkRevokeIdentities).toHaveBeenCalledWith({ identity_ids: ["dep-1", "dep-2"], reason: "keyCompromise" });
    // No client-side fan-out through single-item transitions.
    expect(apiMock.transitionIdentity).not.toHaveBeenCalled();
    expect(await screen.findByText(/Revoked 1 of 2 \(skipped 0, failed 1\)/i)).toBeInTheDocument();
    expect(screen.getByText(/bulk-fail failed: connector queue unavailable/)).toBeInTheDocument();
  });

  it("runs NHI decommission from a served governance signal", async () => {
    apiMock.identities.mockResolvedValue([{ id: "dep-1", name: "payments-api", kind: "api_key", owner_id: "owner-1", status: "deployed" }]);
    apiMock.decommissionNHI.mockResolvedValueOnce({
      capability: "CAP-GOV-04",
      coverage: ["departure", "vendor_term", "inactivity", "revoke", "retire"],
      reason: "vendor termination CAB-22",
      summary: { total_matched: 1, revoked: 1, retired: 0, skipped: 0, failed: 0 },
      items: [
        {
          identity_id: "dep-1",
          name: "payments-api",
          kind: "api_key",
          owner_id: "owner-1",
          signal_type: "vendor_term",
          action: "revoked",
          from: "deployed",
          to: "revoked",
        },
      ],
    });
    const user = userEvent.setup();
    renderIdentities();

    expect(await screen.findByText("payments-api")).toBeInTheDocument();
    const form = screen.getByRole("form", { name: "NHI decommission" });
    await user.selectOptions(within(form).getByLabelText("Signal"), "vendor_term");
    await user.type(within(form).getByLabelText("Vendor"), "Acme SaaS");
    await user.type(within(form).getByLabelText("Reason"), "vendor termination CAB-22");
    await user.click(within(form).getByRole("button", { name: "Decommission" }));

    await waitFor(() => expect(apiMock.decommissionNHI).toHaveBeenCalledTimes(1));
    expect(apiMock.decommissionNHI).toHaveBeenCalledWith({
      reason: "vendor termination CAB-22",
      signals: [{ type: "vendor_term", vendor_name: "Acme SaaS", evidence_refs: ["ui:identities/decommission"] }],
    });
    expect(await screen.findByText(/CAP-GOV-04: matched 1; revoked 1; retired 0; failed 0/)).toBeInTheDocument();
    expect(screen.getByText("payments-api revoked via vendor_term")).toBeInTheDocument();
  });

  it("removes static revocation endpoint prose from the identities page", async () => {
    apiMock.identities.mockResolvedValue([{ id: "dep-9", name: "revocation-docs", status: "deployed" }]);

    renderIdentities();

    expect(await screen.findByText("revocation-docs")).toBeInTheDocument();
    expect(screen.queryByText("Revocation publication")).not.toBeInTheDocument();
    expect(screen.queryByText(/public OCSP and CRL responders/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/Responder paths are tenant-scoped/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/live propagation health/i)).not.toBeInTheDocument();
  });

  it("surfaces a 429 rate-limit with a Retry-After hint (SURFACE-007)", async () => {
    apiMock.identities.mockResolvedValue([{ id: "req-1", name: "svc", status: "requested" }]);
    apiMock.transitionIdentity.mockReset().mockRejectedValue(new ApiError(429, "rate limited", 12));
    const user = userEvent.setup();
    renderIdentities();

    const row = (await screen.findByText("svc")).closest("tr")!;
    // Issue is non-destructive, so it runs without confirmation and hits the 429.
    await user.click(within(row).getByRole("button", { name: /^issue$/i }));
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent(/rate limited/i);
    expect(alert).toHaveTextContent(/12s/);
  });

  it("shows served problem details for denied issue", async () => {
    apiMock.identities.mockResolvedValue([{ id: "req-1", name: "request-only-svc", kind: "x509_certificate", status: "requested" }]);
    apiMock.transitionIdentity.mockReset().mockRejectedValue(
      new ApiError(
        403,
        JSON.stringify({
          detail: "certs:request principals cannot self-issue; a distinct approver is required",
        }),
      ),
    );
    const user = userEvent.setup();
    renderIdentities();

    const row = (await screen.findByText("request-only-svc")).closest("tr")!;
    const issue = within(row).getByRole("button", { name: /^issue$/i });
    await user.click(issue);

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent(/certs:request principals cannot self-issue/i);
    expect(alert).toHaveTextContent(/distinct approver/i);
    expect(issue).toBeDisabled();
    expect(row).toHaveTextContent(/certs:request principals cannot self-issue/i);
  });

  it("moves dual-control approval decisions out of identity rows", async () => {
    apiMock.identities.mockResolvedValue([{ id: "req-1", name: "self-approval-svc", kind: "x509_certificate", status: "requested" }]);
    renderIdentities();

    const row = (await screen.findByText("self-approval-svc")).closest("tr")!;
    expect(within(row).queryByRole("button", { name: /approve issue/i })).not.toBeInTheDocument();
    expect(screen.queryByText("JIT approvals moved to the inbox")).not.toBeInTheDocument();
    expect(screen.queryByRole("link", { name: /review in approvals|open approvals inbox/i })).not.toBeInTheDocument();
  });

  it("keeps the dedicated approvals inbox out of the identities page", async () => {
    apiMock.identities.mockResolvedValue([
      {
        id: "jit-1",
        name: "jit-db",
        kind: "x509_certificate",
        status: "requested",
        attributes: {
          requester: "alice",
          approvals: "1/2",
          grant_expires_at: "2026-06-19T18:00:00Z",
        },
      },
    ]);
    renderIdentities();

    expect(await screen.findByText("jit-db")).toBeInTheDocument();
    expect(screen.queryByText("JIT approvals moved to the inbox")).not.toBeInTheDocument();
    expect(screen.queryByText("alice")).not.toBeInTheDocument();
    expect(screen.queryByText("1/2")).not.toBeInTheDocument();
    expect(screen.queryByText("2026-06-19T18:00:00Z")).not.toBeInTheDocument();
    expect(screen.queryByRole("link", { name: /open approvals inbox/i })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /approve issue for jit-db/i })).not.toBeInTheDocument();
  });

  it("summarizes connector failures for operators and preserves exact receipt evidence behind disclosure", async () => {
    apiMock.identities.mockResolvedValue([{ id: "iss-1", name: "issued-svc", kind: "x509_certificate", status: "issued" }]);
    apiMock.connectorDeliveries.mockResolvedValue({
      items: [
        {
          id: "receipt-1",
          tenant_id: "tenant-1",
          identity_id: "iss-1",
          destination: "connector.deploy",
          connector: "nginx",
          target: "edge-1",
          fingerprint: "abc123",
          status: "failed",
          attempts: 1,
          reason: "plugin_not_loaded",
          detail: "connector is not owned by a loaded signed plugin",
          rollback_ref: "",
          idempotency_key: "event-1",
          created_at: "2026-06-20T00:00:00Z",
          updated_at: "2026-06-20T00:00:00Z",
        },
      ],
    });
    const user = userEvent.setup();
    renderIdentities();

    await user.click((await screen.findAllByText("Delivery and rotation evidence"))[0]);
    await user.click(screen.getByText("Show exact reason"));
    expect(screen.getByText("plugin_not_loaded")).toBeInTheDocument();
    const row = screen.getByText("issued-svc").closest("tr")!;
    expect(row).toHaveTextContent("Delivery needs attention.");
    expect(row).not.toHaveTextContent("plugin_not_loaded");
  });

  it("renders scheduler-backed rotation evidence without the automation preview", async () => {
    apiMock.identities.mockResolvedValue([{ id: "ren-1", name: "manual-renewal-svc", kind: "x509_certificate", status: "deployed" }]);
    apiMock.rotationRuns.mockResolvedValue({
      items: [
        {
          id: "run-1",
          tenant_id: "tenant-1",
          identity_id: "ren-1",
          status: "succeeded",
          trigger: "scheduler",
          reason: "scheduled renewal before expiry",
          predecessor_fingerprint: "old",
          successor_fingerprint: "new",
          rollback_ref: "restore certificate fingerprint old",
          idempotency_key: "event-2",
          created_at: "2026-06-20T00:00:00Z",
          updated_at: "2026-06-20T00:01:00Z",
          completed_at: "2026-06-20T00:01:00Z",
        },
      ],
    });
    const user = userEvent.setup();
    renderIdentities();

    await user.click((await screen.findAllByText("Delivery and rotation evidence"))[0]);
    expect(screen.getAllByText("succeeded").length).toBeGreaterThan(0);
    expect(screen.getAllByText("scheduler").length).toBeGreaterThan(0);
    expect(screen.getByText("restore certificate fingerprint old")).toBeInTheDocument();
    expect(screen.queryByText("Lifecycle automation")).not.toBeInTheDocument();
    expect(screen.queryByText("Automation layout preview")).not.toBeInTheDocument();
    expect(screen.queryByText("Renew before")).not.toBeInTheDocument();
    expect(screen.queryByText("Alert before")).not.toBeInTheDocument();
    expect(screen.queryByText("Dry run")).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /save schedule|run automation/i })).not.toBeInTheDocument();
  });

  it("reports idempotency protection after a successful lifecycle transition", async () => {
    apiMock.identities.mockResolvedValue([{ id: "req-1", name: "idempotent-svc", kind: "x509_certificate", status: "requested" }]);
    const user = userEvent.setup();
    renderIdentities();

    const row = (await screen.findByText("idempotent-svc")).closest("tr")!;
    await user.click(within(row).getByRole("button", { name: /^issue$/i }));

    await waitFor(() => expect(apiMock.transitionIdentity).toHaveBeenCalledWith("req-1", "issued", expect.anything()));
    expect(await screen.findByRole("status")).toHaveTextContent(/Idempotency-Key protects/i);
    expect(screen.getByRole("status")).toHaveTextContent(/duplicate execution/i);
  });

  it("creates (issues) a new identity from the page", async () => {
    apiMock.identities.mockResolvedValue([]);
    const user = userEvent.setup();
    renderIdentities();

    await user.click(await screen.findByRole("button", { name: /add identity/i }));
    await user.type(screen.getByLabelText(/name/i), "svc");
    await user.click(screen.getByRole("button", { name: /create|issue/i }));
    await waitFor(() => expect(apiMock.issueCertificate).toHaveBeenCalledWith(expect.objectContaining({ name: "svc" })));
  });

  it("requires explicit acknowledgement before issuing a wildcard identity", async () => {
    apiMock.identities.mockResolvedValue([]);
    const user = userEvent.setup();
    renderIdentities();

    await user.click(await screen.findByRole("button", { name: /add identity/i }));
    await user.type(screen.getByLabelText(/name/i), "*.payments.example");
    const issue = screen.getByRole("button", { name: /create|issue/i });
    expect(issue).toBeDisabled();
    expect(screen.getByText(/DNS-01 validation is required/i)).toBeInTheDocument();

    await user.click(screen.getByLabelText(/Acknowledge wildcard blast radius/i));
    expect(issue).toBeEnabled();
    await user.click(issue);
    await waitFor(() =>
      expect(apiMock.issueCertificate).toHaveBeenCalledWith({
        name: "*.payments.example",
        wildcardBlastRadiusAcknowledged: true,
      }),
    );
  });

  it("does not record dual-control approval from the identity row", async () => {
    apiMock.identities.mockResolvedValue([{ id: "req-1", name: "needs-approval", status: "requested" }]);
    renderIdentities();

    const row = (await screen.findByText("needs-approval")).closest("tr")!;
    expect(within(row).queryByRole("button", { name: /approve issue/i })).not.toBeInTheDocument();
    expect(screen.queryByRole("link", { name: /review in approvals|open approvals inbox/i })).not.toBeInTheDocument();
    expect(apiMock.approveIdentityAction).not.toHaveBeenCalled();
  });
});
