import { beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { ApiError } from "@/lib/api";
import { ThemeProvider } from "@/components/ThemeProvider";
import { AuthProvider } from "@/auth/AuthProvider";
import { AppRoutes } from "@/App";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    me: vi.fn(),
    profiles: vi.fn(),
    getProfileVersion: vi.fn(),
    createProfile: vi.fn(),
    auditEvents: vi.fn(),
    exportAudit: vi.fn(),
    graph: vi.fn(),
    graphBlastRadius: vi.fn(),
    graphReachable: vi.fn(),
    graphQuery: vi.fn(),
    risk: vi.fn(),
    contextualRiskPriorities: vi.fn(),
    nhiPolicyCompliance: vi.fn(),
    nhiOverPrivilegePosture: vi.fn(),
    nhiStalePosture: vi.fn(),
    nhiStaticPosture: vi.fn(),
    rotationRuns: vi.fn(),
    connectorDeliveries: vi.fn(),
    identities: vi.fn(),
    approveIdentityAction: vi.fn(),
    transitionIdentity: vi.fn(),
  },
}));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: apiMock };
});

function renderAt(path: string) {
  return render(
    <ThemeProvider>
      <AuthProvider>
        <MemoryRouter initialEntries={[path]}>
          <AppRoutes />
        </MemoryRouter>
      </AuthProvider>
    </ThemeProvider>,
  );
}

describe("operational console surface", () => {
  beforeEach(() => {
    for (const mock of Object.values(apiMock)) mock.mockReset();
    apiMock.me.mockResolvedValue({ subject: "user-1", tenant_id: "t1", email: "u@example.test" });
    apiMock.rotationRuns.mockResolvedValue({ items: [] });
    apiMock.connectorDeliveries.mockResolvedValue({ items: [] });
    apiMock.identities.mockResolvedValue([]);
    apiMock.nhiPolicyCompliance.mockResolvedValue(emptyNHIPolicyCompliance());
    apiMock.nhiOverPrivilegePosture.mockResolvedValue(emptyNHIOverPrivilegePosture());
    apiMock.nhiStalePosture.mockResolvedValue(emptyNHIStalePosture());
    apiMock.nhiStaticPosture.mockResolvedValue(emptyNHIStaticPosture());
    apiMock.contextualRiskPriorities.mockResolvedValue(emptyContextualRiskPriorities());
    apiMock.approveIdentityAction.mockResolvedValue({ resource: "req-1", action: "issue", approver: "ra", approvals: 1 });
    apiMock.transitionIdentity.mockResolvedValue({ id: "req-1", name: "requested-svc", status: "retired" });
  });

  it("routes to profiles, lists versions, and creates a profile", async () => {
    apiMock.profiles
      .mockResolvedValueOnce([{ id: "p1", name: "server", version: 1, active: true, created_by: "ra" }])
      .mockResolvedValueOnce([{ id: "p2", name: "server", version: 2, active: true, created_by: "ra" }]);
    apiMock.createProfile.mockResolvedValue({ id: "p1", name: "server", version: 2, active: true });
    const user = userEvent.setup();
    renderAt("/profiles");

    expect(await screen.findByRole("heading", { name: "Profiles" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /New profile/i })).toBeInTheDocument();
    expect(await screen.findByText("server")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: /New profile/i }));
    await user.clear(screen.getByLabelText(/Profile name/i));
    await user.type(screen.getByLabelText(/Profile name/i), "server");
    await user.click(screen.getByRole("button", { name: /Create profile/i }));

    await waitFor(() =>
      expect(apiMock.createProfile).toHaveBeenCalledWith({
        name: "server",
        spec: {
          allowed_key_algorithms: ["ECDSA"],
          min_ecdsa_bits: 256,
          allowed_ekus: ["serverAuth"],
          max_validity: "2160h",
          allowed_protocols: ["api", "acme"],
          allowed_dns_suffixes: ["example.com"],
        },
      }),
    );
  });

  it("surfaces served profile validation problems from the JSON fallback", async () => {
    apiMock.profiles.mockResolvedValue([]);
    apiMock.createProfile.mockRejectedValue(new ApiError(422, JSON.stringify({ detail: "max_validity exceeds the tenant profile ceiling" })));
    const user = userEvent.setup();
    renderAt("/profiles");

    await user.click(await screen.findByRole("button", { name: /New profile/i }));
    await user.type(screen.getByLabelText(/Profile name/i), "oversized");
    await user.click(screen.getByRole("button", { name: /JSON editor/i }));
    fireEvent.change(screen.getByLabelText(/JSON spec/i), {
      target: { value: '{"max_validity":"999999h"}' },
    });
    await user.click(screen.getByRole("button", { name: /Create profile/i }));

    expect(await screen.findByRole("alert")).toHaveTextContent("max_validity exceeds the tenant profile ceiling");
  });

  it("loads concrete profile versions and diffs selected rules against the active version", async () => {
    const versionOne = {
      id: "p1",
      name: "server",
      version: 1,
      active: false,
      created_by: "ra",
      spec: {
        allowed_key_algorithms: ["RSA"],
        min_rsa_bits: 2048,
        allowed_ekus: ["serverAuth"],
        max_validity: "720h",
      },
    };
    const versionTwo = {
      id: "p2",
      name: "server",
      version: 2,
      active: true,
      created_by: "ra",
      spec: {
        allowed_key_algorithms: ["ECDSA"],
        min_ecdsa_bits: 256,
        allowed_ekus: ["serverAuth"],
        max_validity: "2160h",
        allowed_dns_suffixes: ["example.com"],
      },
    };
    apiMock.profiles.mockResolvedValue([versionOne, versionTwo]);
    apiMock.getProfileVersion.mockImplementation((_name: string, version: number) => Promise.resolve(version === 1 ? versionOne : versionTwo));
    const user = userEvent.setup();
    renderAt("/profiles");

    await user.click(await screen.findByRole("button", { name: "View server version 1" }));
    expect(await screen.findByRole("heading", { name: "server version 1" })).toBeInTheDocument();
    expect(screen.getByText(/does not rewrite past decisions/i)).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: /Diff version/i }));

    await waitFor(() => expect(apiMock.getProfileVersion).toHaveBeenCalledWith("server", 2));
    expect(await screen.findByText(/Comparing selected v1 to v2/i)).toBeInTheDocument();
    expect(screen.getByText("max_validity")).toBeInTheDocument();
    expect(screen.getAllByText("Changed").length).toBeGreaterThan(0);
  });

  it("routes to audit events and exports signed evidence", async () => {
    apiMock.auditEvents.mockResolvedValue([
      {
        sequence: 7,
        id: "evt-7",
        type: "identity.issued",
        tenant_id: "t1",
        time: "2026-06-17T12:00:00Z",
        hash: "abc",
        actor: { email: "ra@example.test" },
        data: { resource_id: "cert-1" },
      },
    ]);
    apiMock.exportAudit.mockResolvedValue({ format: "jws", bundle: "sealed.bundle" });
    const user = userEvent.setup();
    renderAt("/audit");

    expect(await screen.findByRole("heading", { name: "Audit" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /Audit/i })).toHaveAttribute("href", "/audit");
    expect(await screen.findByText("identity.issued")).toBeInTheDocument();
    expect(screen.getByRole("table", { name: "Tenant audit events" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Columns/i })).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: /Export evidence/i }));
    expect(await screen.findByText("jws: sealed.bundle")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Download signed bundle" })).toHaveAttribute("download", "audit-evidence.jws.txt");
    expect(apiMock.exportAudit).toHaveBeenCalledWith({ limit: 50 });
  });

  it("filters audit events through served params and opens the event detail drawer", async () => {
    apiMock.auditEvents
      .mockResolvedValueOnce([{ sequence: 1, id: "evt-1", type: "identity.requested", tenant_id: "t1", time: "2026-06-17T11:00:00Z" }])
      .mockResolvedValueOnce([
        {
          sequence: 7,
          id: "evt-7",
          type: "identity.issued",
          tenant_id: "t1",
          time: "2026-06-17T12:00:00Z",
          hash: "sha256:abcdef0123456789",
          actor: { email: "ra@example.test" },
          data: { resource_id: "cert/payments", reason: "approved by second RA" },
        },
      ]);
    const user = userEvent.setup();
    renderAt("/audit");

    expect(await screen.findByText("identity.requested")).toBeInTheDocument();

    await user.type(screen.getByLabelText("Type"), "identity.issued");
    await user.type(screen.getByLabelText("Search"), "payments");
    await user.type(screen.getByLabelText("Since"), "2026-06-17T00:00:00Z");
    await user.clear(screen.getByLabelText("Limit"));
    await user.type(screen.getByLabelText("Limit"), "25");
    await user.click(screen.getByRole("button", { name: "Apply filters" }));

    await waitFor(() =>
      expect(apiMock.auditEvents).toHaveBeenLastCalledWith({
        type: "identity.issued",
        since: "2026-06-17T00:00:00Z",
        q: "payments",
        limit: 25,
      }),
    );
    expect(await screen.findByText("cert/payments")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "View event 7" }));

    expect(await screen.findByRole("heading", { name: "Event detail" })).toBeInTheDocument();
    expect(screen.getAllByText("sha256:abcdef0123456789").length).toBeGreaterThan(0);
    expect(screen.getAllByText(/approved by second RA/).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/ra@example.test/).length).toBeGreaterThan(0);
  });

  it("shows audit empty and permission-denied states without leaking tenant details", async () => {
    apiMock.auditEvents.mockResolvedValueOnce([]);
    const empty = renderAt("/audit");

    expect(await screen.findByText("No audit events match these filters")).toBeInTheDocument();
    expect(empty.container.querySelector('[data-state-primitive="empty"]')).toBeInTheDocument();
    empty.unmount();

    apiMock.auditEvents.mockReset();
    apiMock.auditEvents.mockRejectedValue(new ApiError(403, JSON.stringify({ detail: "tenant t2 audit stream exists but is forbidden" })));
    renderAt("/audit");

    expect(await screen.findByText("Permission denied")).toBeInTheDocument();
    expect(screen.getByRole("alert")).toHaveTextContent("Your session cannot read tenant audit evidence.");
    expect(screen.queryByText(/tenant t2/i)).not.toBeInTheDocument();
  });

  it("surfaces audit export problem+json errors", async () => {
    apiMock.auditEvents.mockResolvedValue([{ sequence: 7, id: "evt-7", type: "identity.issued", tenant_id: "t1", time: "2026-06-17T12:00:00Z", hash: "abc" }]);
    apiMock.exportAudit.mockRejectedValue(new ApiError(422, JSON.stringify({ detail: "audit export window too large" })));
    const user = userEvent.setup();
    renderAt("/audit");

    await screen.findByText("identity.issued");
    await user.click(screen.getByRole("button", { name: /Export evidence/i }));

    expect(await screen.findByText(/Could not export evidence: audit export window too large/)).toBeInTheDocument();
  });

  it("traps focus in the operations rejection dialog and returns focus to the opener", async () => {
    apiMock.identities.mockResolvedValue([
      {
        id: "req-1",
        name: "requested-svc",
        status: "requested",
        attributes: { requester: "app-team", approvals: "1/2", grant_expires_at: "2026-07-01T00:00:00Z" },
      },
    ]);
    const user = userEvent.setup();
    renderAt("/operations");

    const opener = await screen.findByRole("button", { name: "Reject issue for requested-svc" });
    await user.click(opener);

    const dialog = await screen.findByRole("dialog", { name: "Reject issue for requested-svc" });
    const reason = within(dialog).getByLabelText("Reason");
    const cancel = within(dialog).getByRole("button", { name: "Cancel" });

    expect(reason).toHaveFocus();

    await user.tab({ shift: true });
    expect(cancel).toHaveFocus();

    await user.tab();
    expect(reason).toHaveFocus();

    await user.keyboard("{Escape}");
    expect(screen.queryByRole("dialog", { name: "Reject issue for requested-svc" })).not.toBeInTheDocument();
    expect(opener).toHaveFocus();
  });

  it("routes to graph inventory and runs blast-radius analysis", async () => {
    apiMock.graph.mockResolvedValue({
      nodes: [
        { id: "cert:1", kind: "credential", name: "payments-cert" },
        { id: "res:1", kind: "resource", name: "payments-api" },
      ],
      edges: [{ from: "cert:1", to: "res:1", type: "DEPLOYED_TO" }],
    });
    apiMock.graphBlastRadius.mockResolvedValue({
      node: { id: "cert:1", kind: "credential", name: "payments-cert" },
      affected: [{ id: "res:1", kind: "resource", name: "payments-api" }],
      by_kind: {},
    });
    apiMock.graphReachable.mockResolvedValue({
      from: "cert:1",
      nodes: [{ id: "res:1", kind: "resource", name: "payments-api" }],
    });
    const user = userEvent.setup();
    renderAt("/graph");

    expect(await screen.findByRole("heading", { name: "Graph" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /Graph/i })).toHaveAttribute("href", "/graph");
    expect((await screen.findAllByText("payments-cert")).length).toBeGreaterThan(0);

    await user.click(screen.getByRole("button", { name: "Analyze selected node" }));
    await waitFor(() => expect(apiMock.graphBlastRadius).toHaveBeenCalledWith("cert:1"));
    expect(screen.getByTestId("blast-radius-count")).toHaveTextContent("1");
  });

  it("renders graph nodes and edges, filters by kind, and opens URL-safe node detail links", async () => {
    apiMock.graph.mockResolvedValue({
      nodes: [
        { id: "cert:cert/unsafe", kind: "credential", name: "payments-cert", attrs: { serial: "01" } },
        { id: "workload:payments", kind: "workload", name: "payments-api", attrs: { owner: "team-a" } },
      ],
      edges: [{ from: "cert:cert/unsafe", to: "workload:payments", type: "DEPLOYED_TO" }],
    });
    const user = userEvent.setup();
    renderAt("/graph");

    expect((await screen.findAllByText("payments-cert")).length).toBeGreaterThan(0);
    expect(screen.getByTestId("graph-visualization")).toBeInTheDocument();
    expect(screen.getAllByTestId("graph-node")).toHaveLength(2);
    expect(screen.getAllByTestId("graph-node").map((node) => node.getAttribute("data-node-kind"))).toEqual(["credential", "workload"]);
    expect(screen.getAllByTestId("graph-edge")).toHaveLength(1);
    expect(screen.getByTestId("graph-text-fallback")).toBeInTheDocument();
    expect(screen.getByText("The credential is deployed to that workload or resource.")).toBeInTheDocument();

    await user.clear(screen.getByLabelText("Search"));
    await user.type(screen.getByLabelText("Search"), "payments-api");
    expect(screen.queryByRole("button", { name: "Choose payments-cert" })).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Select graph node payments-api" }));
    expect(screen.getByRole("heading", { name: "Node detail" })).toBeInTheDocument();
    expect(screen.getAllByText("workload:payments").length).toBeGreaterThan(0);

    await user.clear(screen.getByLabelText("Search"));
    await user.click(screen.getByRole("button", { name: "Graph node payments-cert" }));
    expect(screen.getAllByText("cert:cert/unsafe").length).toBeGreaterThan(0);

    await user.click(screen.getByLabelText("Show Deployed to edges"));
    expect(screen.queryAllByTestId("graph-edge")).toHaveLength(0);
    await user.click(screen.getByRole("button", { name: "Clear filters" }));
    expect(screen.getAllByTestId("graph-edge")).toHaveLength(1);

    await user.selectOptions(screen.getByLabelText("Kind"), "credential");
    expect(screen.getAllByTestId("graph-node-name").map((cell) => cell.textContent)).toEqual(["payments-cert"]);

    await user.click(screen.getByRole("button", { name: "Select payments-cert" }));

    expect(await screen.findByRole("heading", { name: "Node detail" })).toBeInTheDocument();
    expect(screen.getAllByText("cert:cert/unsafe").length).toBeGreaterThan(0);
    expect(screen.getByText("01")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Certificate detail" })).toHaveAttribute("href", "/certificates?credential=cert%2Funsafe");
    expect(screen.getByRole("link", { name: "Risk row" })).toHaveAttribute("href", "/risk?node=cert%3Acert%2Funsafe");
    expect(screen.getByRole("link", { name: "Audit evidence" })).toHaveAttribute("href", "/audit?node=cert%3Acert%2Funsafe");
  });

  it("renders blast-radius by-kind, reachable nodes, graph query rows, and export", async () => {
    apiMock.graph.mockResolvedValue({
      nodes: [
        { id: "cert:payments", kind: "credential", name: "payments-cert" },
        { id: "res:db", kind: "resource", name: "payments-db" },
      ],
      edges: [{ from: "cert:payments", to: "res:db", type: "GRANTS_ACCESS" }],
    });
    apiMock.graphBlastRadius.mockResolvedValue({
      node: { id: "cert:payments", kind: "credential", name: "payments-cert" },
      affected: [{ id: "res:db", kind: "resource", name: "payments-db" }],
      by_kind: { resource: 1 },
    });
    apiMock.graphReachable.mockResolvedValue({
      from: "cert:payments",
      nodes: [{ id: "res:db", kind: "resource", name: "payments-db" }],
    });
    apiMock.graphQuery.mockResolvedValue({ rows: [{ credential: "payments-cert", resource: "payments-db" }] });
    const user = userEvent.setup();
    renderAt("/graph");

    await waitFor(() => expect(screen.getAllByTestId("graph-node-name")[0]).toHaveTextContent("payments-cert"));
    await user.click(screen.getByRole("button", { name: "Analyze selected node" }));
    await waitFor(() => expect(apiMock.graphBlastRadius).toHaveBeenCalledWith("cert:payments"));
    expect(apiMock.graphReachable).toHaveBeenCalledWith("cert:payments");
    expect(await screen.findByRole("heading", { name: "Blast-radius paths and by-kind summary" })).toBeInTheDocument();
    expect(screen.getAllByText("resource").length).toBeGreaterThan(0);
    expect(screen.getAllByText("payments-db").length).toBeGreaterThan(0);
    expect(await screen.findByRole("heading", { name: "Reachable nodes" })).toBeInTheDocument();

    await user.click(screen.getByRole("tab", { name: "Advanced query" }));
    fireEvent.change(screen.getByLabelText("Cypher-style query"), {
      target: { value: "MATCH (a)-[e]->(b) RETURN a,b" },
    });
    await user.click(screen.getByRole("button", { name: "Run graph query" }));
    await waitFor(() => expect(apiMock.graphQuery).toHaveBeenCalledWith("MATCH (a)-[e]->(b) RETURN a,b"));
    expect((await screen.findAllByText(/payments-db/)).length).toBeGreaterThan(0);
    expect(screen.getByRole("link", { name: "Export query rows" })).toHaveAttribute("download", "graph-query-results.json");
  });

  it("shows graph empty and permission-denied states without leaking tenant details", async () => {
    apiMock.graph.mockResolvedValueOnce({ nodes: [], edges: [] });
    const empty = renderAt("/graph");

    expect(await screen.findByText("No graph nodes yet")).toBeInTheDocument();
    expect(empty.container.querySelector('[data-state-primitive="empty"]')).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Analyze selected node" })).toBeDisabled();
    empty.unmount();

    apiMock.graph.mockRejectedValue(new ApiError(403, JSON.stringify({ detail: "tenant t2 graph scope exists but is forbidden" })));
    renderAt("/graph");

    expect(await screen.findByText("Permission denied")).toBeInTheDocument();
    expect(screen.getByRole("alert")).toHaveTextContent("Your session cannot read the credential graph for this tenant.");
    expect(screen.queryByText(/tenant t2/i)).not.toBeInTheDocument();
  });

  it("shows served graph problem details and 429 retry hints for graph actions", async () => {
    apiMock.graph.mockResolvedValue({
      nodes: [{ id: "cert:payments", kind: "credential", name: "payments-cert" }],
      edges: [],
    });
    apiMock.graphBlastRadius.mockResolvedValue({ node: { id: "cert:payments", kind: "credential", name: "payments-cert" }, affected: [], by_kind: {} });
    apiMock.graphReachable.mockRejectedValue(new ApiError(429, "queue full", 7));
    apiMock.graphQuery.mockRejectedValue(new ApiError(422, JSON.stringify({ detail: "query parser rejected RETURN" })));
    const user = userEvent.setup();
    renderAt("/graph");

    await waitFor(() => expect(screen.getAllByTestId("graph-node-name")[0]).toHaveTextContent("payments-cert"));
    await user.click(screen.getByRole("button", { name: "Analyze selected node" }));
    expect(await screen.findByText(/Could not compute reachability: retry in 7s/)).toBeInTheDocument();

    await user.click(screen.getByRole("tab", { name: "Advanced query" }));
    await user.clear(screen.getByLabelText("Cypher-style query"));
    await user.type(screen.getByLabelText("Cypher-style query"), "RETURN");
    await user.click(screen.getByRole("button", { name: "Run graph query" }));
    expect(await screen.findByText(/Could not run graph query: query parser rejected RETURN/)).toBeInTheDocument();
  });

  it("routes to risk, expands all six served components, and sends server-side sort and filters", async () => {
    apiMock.risk.mockResolvedValue([
      riskRow({
        credential_id: "cert-root",
        subject: "root-ca.example.test",
        score: 91,
        owner_active: false,
        components: { age: 0.2, rotation: 0.4, privilege: 0.9, exposure: 0.95, owner: 1, sensitivity: 0.7 },
      }),
      riskRow({
        credential_id: "cert-old",
        subject: "old-leaf.example.test",
        score: 40,
        owner_active: true,
        components: { age: 0.97, rotation: 0.3, privilege: 0.2, exposure: 0.1, owner: 0, sensitivity: 0.1 },
      }),
    ]);
    apiMock.nhiOverPrivilegePosture.mockResolvedValue({
      ...emptyNHIOverPrivilegePosture(),
      summary: { total_analyzed: 2, overprivileged: 1, critical: 0, high: 1, medium: 0, low: 0, least_privilege_plans: 1, unused_grants: 2, wildcard_grants: 1 },
      findings: [
        {
          inventory_id: "finding/oauth-1",
          kind: "oauth_app",
          source: "discovery_finding",
          display_name: "legacy-github-app",
          status: "open",
          severity: "high",
          risk_score: 82,
          finding_types: ["unused_grants", "usage_driven_scope_delta"],
          granted_scopes: ["repo", "admin:org", "workflow"],
          used_scopes: ["repo"],
          unused_scopes: ["admin:org", "workflow"],
          recommended_scopes: ["repo"],
          unused_ratio: 0.67,
          recommendation: "Remove unused grants admin:org, workflow; keep observed least-privilege grants repo.",
          evidence_refs: ["inventory:finding/oauth-1", "metadata:granted_permissions", "metadata:observed_permissions"],
        },
      ],
    });
    apiMock.nhiStalePosture.mockResolvedValue({
      ...emptyNHIStalePosture(),
      summary: { total_analyzed: 5, findings: 3, stale: 2, dormant: 1, unused: 1, orphaned: 1, critical: 0, high: 1, medium: 2, low: 0, recommendations: 3 },
      findings: [
        {
          inventory_id: "finding/pat-1",
          kind: "token",
          source: "discovery_finding",
          display_name: "dormant-github-pat",
          owner_status: "owned",
          status: "open",
          severity: "high",
          risk_score: 88,
          finding_types: ["stale_activity", "dormant_activity"],
          activity_age_days: 420,
          created_age_days: 420,
          created_at: "2025-05-01T00:00:00Z",
          recommendation: "Quarantine or revoke the dormant NHI unless the owner reattests a current workload dependency.",
          evidence_refs: ["inventory:finding/pat-1", "metadata:last_used_at"],
        },
      ],
    });
    apiMock.nhiStaticPosture.mockResolvedValue({
      ...emptyNHIStaticPosture(),
      summary: { total_analyzed: 4, findings: 2, long_lived: 1, static_credentials: 2, no_expiry: 1, rotation_overdue: 2, critical: 1, high: 1, medium: 0, low: 0, recommendations: 2 },
      findings: [
        {
          inventory_id: "identity/static-1",
          kind: "api_key",
          source: "identity",
          display_name: "legacy-static-api-key",
          owner_status: "owned",
          status: "deployed",
          severity: "critical",
          risk_score: 96,
          finding_types: ["long_lived_credential", "static_credential", "rotation_overdue"],
          credential_age_days: 500,
          ttl_days: 1000,
          rotation_age_days: 500,
          created_at: "2025-02-01T00:00:00Z",
          recommendation: "Shorten the credential lifetime and rotate it before reissuing with an expiry-bound profile.",
          evidence_refs: ["inventory:identity/static-1", "metadata:expires_at", "metadata:last_rotated_at"],
        },
      ],
    });
    apiMock.nhiPolicyCompliance.mockResolvedValue({
      ...emptyNHIPolicyCompliance(),
      summary: {
        total_analyzed: 3,
        compliant: 1,
        violations: 2,
        rotation_violations: 1,
        scope_violations: 2,
        geo_violations: 1,
        expiry_violations: 1,
        business_purpose_missing: 1,
        critical: 1,
        high: 1,
        medium: 0,
        low: 0,
      },
      findings: [
        {
          inventory_id: "identity/governed-ci-token",
          kind: "api_key",
          source: "identity",
          display_name: "governed-ci-token",
          status: "deployed",
          policy_status: "violating",
          severity: "critical",
          risk_score: 96,
          violation_types: ["rotation_overdue", "scope_out_of_policy", "geo_out_of_policy", "business_purpose_missing"],
          disallowed_scopes: ["admin:org"],
          disallowed_geos: ["RU"],
          recommendation: "Bring the NHI back inside policy: rotate the credential; remove disallowed scopes admin:org.",
          evidence_refs: ["inventory:identity/governed-ci-token", "metadata:allowed_scopes", "metadata:business_purpose"],
        },
      ],
    });
    apiMock.contextualRiskPriorities.mockResolvedValue({
      ...emptyContextualRiskPriorities(),
      summary: { total_analyzed: 2, priorities: 2, critical: 1, high: 0, medium: 1, low: 0, high_blast_radius: 1, weak_crypto_context: 1, orphaned: 0, near_expiry: 1, recommendations: 2 },
      priorities: [
        {
          rank: 1,
          credential_id: "cert-payments",
          subject: "payments-api.prod",
          kind: "certificate",
          severity: "critical",
          contextual_score: 96.4,
          base_score: 64.4,
          blast_radius: 4,
          resource_blast_radius: 1,
          workload_blast_radius: 0,
          credential_blast_radius: 0,
          crypto_asset_blast_radius: 3,
          weak_crypto_context: 3,
          privilege: 2,
          sensitivity: 1,
          owner_active: true,
          expires_at: "2026-07-29T00:00:00Z",
          components: { age: 0.8, rotation: 0.7, privilege: 0.7, exposure: 0.2, owner: 0, sensitivity: 0.5 },
          priority_reasons: ["high_blast_radius", "weak_crypto_context"],
          evidence_refs: ["credential:cert-payments", "graph:blast-radius:cert:cert-payments"],
          recommended_action: "Rotate and redeploy before lower-blast-radius work; review affected resources and weak crypto assets first.",
        },
      ],
    });
    const user = userEvent.setup();
    renderAt("/risk");

    expect(await screen.findByRole("heading", { name: "Credential risk" })).toBeInTheDocument();
    await waitFor(() => expect(apiMock.risk).toHaveBeenCalledWith({ sort: "score" }));
    await waitFor(() => expect(apiMock.contextualRiskPriorities).toHaveBeenCalledTimes(1));
    await waitFor(() => expect(apiMock.nhiPolicyCompliance).toHaveBeenCalledTimes(1));
    await waitFor(() => expect(apiMock.nhiOverPrivilegePosture).toHaveBeenCalledTimes(1));
    await waitFor(() => expect(apiMock.nhiStalePosture).toHaveBeenCalledTimes(1));
    await waitFor(() => expect(apiMock.nhiStaticPosture).toHaveBeenCalledTimes(1));
    expect(screen.getByRole("heading", { name: "Contextual priorities" })).toBeInTheDocument();
    expect(screen.getByText(/CAP-POST-05: 2 prioritized of 2 credentials; 1 high-blast-radius/)).toBeInTheDocument();
    expect(screen.getByText("payments-api.prod")).toBeInTheDocument();
    expect(screen.getByText("high_blast_radius, weak_crypto_context")).toBeInTheDocument();
    expect(screen.getByText("4 affected; 1 resources, 3 crypto assets")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "NHI policy compliance" })).toBeInTheDocument();
    expect(screen.getByText(/CAP-GOV-03: 2 policy violations across 3 governed NHIs/)).toBeInTheDocument();
    expect(screen.getByText("governed-ci-token")).toBeInTheDocument();
    expect(screen.getByText("rotation_overdue, scope_out_of_policy, geo_out_of_policy, business_purpose_missing")).toBeInTheDocument();
    expect(screen.getByText("Scopes: admin:org / Geos: RU")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "NHI over-privilege" })).toBeInTheDocument();
    expect(screen.getByText(/CAP-POST-01: 1 over-privileged of 2 usage-backed NHIs; 2 unused grants/)).toBeInTheDocument();
    expect(screen.getByText("legacy-github-app")).toBeInTheDocument();
    expect(screen.getByText("admin:org, workflow")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Stale and dormant NHIs" })).toBeInTheDocument();
    expect(screen.getByText(/CAP-POST-02: 3 stale, unused, orphaned, or dormant of 5 analyzed NHIs/)).toBeInTheDocument();
    expect(screen.getByText("dormant-github-pat")).toBeInTheDocument();
    expect(screen.getByText("stale_activity, dormant_activity")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Static credentials" })).toBeInTheDocument();
    expect(screen.getByText(/CAP-POST-03: 2 static or long-lived of 4 analyzed NHIs/)).toBeInTheDocument();
    expect(screen.getByText("legacy-static-api-key")).toBeInTheDocument();
    expect(screen.getByText("long_lived_credential, static_credential, rotation_overdue")).toBeInTheDocument();
    expect(screen.getAllByTestId("risk-subject").map((cell) => cell.textContent)).toEqual(["root-ca.example.test", "old-leaf.example.test"]);
    expect(screen.queryByRole("heading", { name: "Risk band legend" })).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Risk bands" })).toHaveAccessibleDescription(/Critical 90-100/);

    const rootRow = screen.getByText("root-ca.example.test").closest("tr")!;
    expect(within(rootRow).getByText("High")).toHaveAttribute("title", "Raw privilege value 2");
    expect(within(rootRow).getByText("Internal")).toHaveAttribute("title", "Raw sensitivity value 1");
    await user.click(within(rootRow).getByRole("button", { name: /show factors/i }));
    for (const factor of ["age", "rotation", "privilege", "exposure", "owner", "sensitivity"]) {
      expect(screen.getByTestId(`risk-factor-${factor}`)).toBeInTheDocument();
    }
    expect(screen.getByTestId("risk-factor-exposure")).toHaveTextContent("95");
    expect(screen.getAllByText(/raw 2/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/raw 1/i).length).toBeGreaterThan(0);

    await user.click(screen.getByRole("button", { name: /expires/i }));
    await waitFor(() => expect(apiMock.risk).toHaveBeenLastCalledWith({ sort: "expiry" }));

    await user.clear(screen.getByLabelText("Minimum score"));
    await user.type(screen.getByLabelText("Minimum score"), "80");
    await user.selectOptions(screen.getByLabelText("Privilege"), "3");
    await user.type(screen.getByLabelText("Owner"), "platform");
    await user.click(screen.getByRole("button", { name: "Apply risk filters" }));
    await waitFor(() =>
      expect(apiMock.risk).toHaveBeenLastCalledWith({
        sort: "expiry",
        minScore: 80,
        privilege: 3,
        owner: "platform",
      }),
    );
  });

  it("links a risk row to certificate detail, graph blast-radius, owner state, and audit evidence", async () => {
    apiMock.risk.mockResolvedValue([
      riskRow({
        credential_id: "cert/unsafe",
        subject: "edge.example.test",
        score: 87,
        owner_active: false,
        components: { age: 0.3, rotation: 1, privilege: 0.6, exposure: 0.8, owner: 1, sensitivity: 0.4 },
      }),
    ]);
    const user = userEvent.setup();
    renderAt("/risk");

    const row = (await screen.findByText("edge.example.test")).closest("tr")!;
    await user.click(within(row).getByRole("button", { name: /show factors/i }));

    expect(screen.getByRole("link", { name: "Credential detail" })).toHaveAttribute("href", "/certificates?credential=cert%2Funsafe");
    expect(screen.getByRole("link", { name: "Owner status orphaned" })).toHaveAttribute("href", "/owners?status=orphaned");
    expect(screen.getByRole("link", { name: "Graph blast radius" })).toHaveAttribute("href", "/graph?node=cert%3Acert%2Funsafe");
    expect(screen.getByRole("link", { name: "Audit evidence" })).toHaveAttribute("href", "/audit?credential=cert%2Funsafe");
  });

  it("shows the certificate-only risk scope and does not fabricate non-certificate scores", async () => {
    apiMock.risk.mockResolvedValue([
      riskRow({
        credential_id: "ssh-1",
        subject: "ssh-key-prod",
        kind: "ssh_key",
        score: 99,
        components: { age: 1, rotation: 1, privilege: 1, exposure: 1, owner: 1, sensitivity: 1 },
      }),
    ]);
    renderAt("/risk");

    expect(await screen.findByText("Certificates only today")).toBeInTheDocument();
    expect(screen.getAllByText(/Risk scoring covers certificates today/i).length).toBeGreaterThan(0);
    expect(screen.getByText(/1 non-certificate risk record is waiting/i)).toBeInTheDocument();
    expect(screen.queryByText("ssh-key-prod")).not.toBeInTheDocument();
    expect(screen.getByText(/No certificate risk scores match/i)).toBeInTheDocument();
  });
});

function riskRow(overrides: Partial<ReturnType<typeof riskRowBase>> = {}) {
  return { ...riskRowBase(), ...overrides, components: { ...riskRowBase().components, ...overrides.components } };
}

function emptyNHIPolicyCompliance() {
  return {
    capability: "CAP-GOV-03",
    generated_at: "2026-06-29T00:00:00Z",
    coverage: ["managed_identities", "discovery_findings", "rotation_cadence", "allowed_scopes", "allowed_geographies", "expiry_policy", "business_purpose"],
    summary: {
      total_analyzed: 0,
      compliant: 0,
      violations: 0,
      rotation_violations: 0,
      scope_violations: 0,
      geo_violations: 0,
      expiry_violations: 0,
      business_purpose_missing: 0,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
    },
    findings: [],
    recommended_actions: [],
    evidence_refs: ["projection:nhi_inventory"],
  };
}

function emptyNHIOverPrivilegePosture() {
  return {
    capability: "CAP-POST-01",
    generated_at: "2026-06-29T00:00:00Z",
    coverage: ["managed_identities", "discovery_findings", "usage_driven_scope_delta", "least_privilege_recommendations"],
    summary: { total_analyzed: 0, overprivileged: 0, critical: 0, high: 0, medium: 0, low: 0, least_privilege_plans: 0, unused_grants: 0, wildcard_grants: 0 },
    findings: [],
  };
}

function emptyNHIStalePosture() {
  return {
    capability: "CAP-POST-02",
    generated_at: "2026-06-29T00:00:00Z",
    coverage: ["managed_identities", "discovery_findings", "stale_activity", "unused_no_activity", "orphaned_detection", "dormant_detection"],
    thresholds: { stale_activity_days: 90, dormant_activity_days: 365, unused_no_activity_days: 90 },
    summary: { total_analyzed: 0, findings: 0, stale: 0, dormant: 0, unused: 0, orphaned: 0, critical: 0, high: 0, medium: 0, low: 0, recommendations: 0 },
    findings: [],
  };
}

function emptyNHIStaticPosture() {
  return {
    capability: "CAP-POST-03",
    generated_at: "2026-06-29T00:00:00Z",
    coverage: ["managed_identities", "discovery_findings", "long_lived_credentials", "static_credential_detection", "no_expiry_detection", "rotation_age"],
    thresholds: { long_lived_credential_days: 365, rotation_overdue_days: 180, no_expiry_minimum_age_days: 90 },
    summary: { total_analyzed: 0, findings: 0, long_lived: 0, static_credentials: 0, no_expiry: 0, rotation_overdue: 0, critical: 0, high: 0, medium: 0, low: 0, recommendations: 0 },
    findings: [],
  };
}

function emptyContextualRiskPriorities() {
  return {
    capability: "CAP-POST-05",
    generated_at: "2026-06-29T00:00:00Z",
    coverage: ["credential_risk_scores", "graph_blast_radius", "resource_reachability", "cbom_crypto_context", "owner_and_rotation_context"],
    summary: { total_analyzed: 0, priorities: 0, critical: 0, high: 0, medium: 0, low: 0, high_blast_radius: 0, weak_crypto_context: 0, orphaned: 0, near_expiry: 0, recommendations: 0 },
    priorities: [],
  };
}

function riskRowBase() {
  return {
    credential_id: "cert-1",
    subject: "svc.example.test",
    kind: "certificate",
    privilege: 2,
    sensitivity: 1,
    exposure: 3,
    owner_active: true,
    expires_at: "2026-07-01T00:00:00Z",
    score: 50,
    components: {
      age: 0.1,
      rotation: 0.2,
      privilege: 0.3,
      exposure: 0.4,
      owner: 0,
      sensitivity: 0.5,
    },
  };
}
