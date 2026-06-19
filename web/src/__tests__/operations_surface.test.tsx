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
  });

  it("routes to profiles, lists versions, and creates a profile", async () => {
    apiMock.profiles
      .mockResolvedValueOnce([{ id: "p1", name: "server", version: 1, active: true, created_by: "ra" }])
      .mockResolvedValueOnce([{ id: "p2", name: "server", version: 2, active: true, created_by: "ra" }]);
    apiMock.createProfile.mockResolvedValue({ id: "p1", name: "server", version: 2, active: true });
    const user = userEvent.setup();
    renderAt("/profiles");

    expect(await screen.findByRole("heading", { name: "Profiles" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /Profiles/i })).toHaveAttribute("href", "/profiles");
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
    apiMock.createProfile.mockRejectedValue(
      new ApiError(422, JSON.stringify({ detail: "max_validity exceeds the tenant profile ceiling" })),
    );
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
    apiMock.getProfileVersion.mockImplementation((_name: string, version: number) =>
      Promise.resolve(version === 1 ? versionOne : versionTwo),
    );
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

    await user.click(screen.getByRole("button", { name: /Export evidence/i }));
    expect(await screen.findByText("jws: sealed.bundle")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Download signed bundle" })).toHaveAttribute(
      "download",
      "audit-evidence.jws.txt",
    );
    expect(apiMock.exportAudit).toHaveBeenCalledWith({ limit: 50 });
  });

  it("filters audit events through served params and opens the event detail drawer", async () => {
    apiMock.auditEvents
      .mockResolvedValueOnce([
        { sequence: 1, id: "evt-1", type: "identity.requested", tenant_id: "t1", time: "2026-06-17T11:00:00Z" },
      ])
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
    apiMock.auditEvents.mockRejectedValue(
      new ApiError(403, JSON.stringify({ detail: "tenant t2 audit stream exists but is forbidden" })),
    );
    renderAt("/audit");

    expect(await screen.findByText("Permission denied")).toBeInTheDocument();
    expect(screen.getByRole("alert")).toHaveTextContent("Your session cannot read tenant audit evidence.");
    expect(screen.queryByText(/tenant t2/i)).not.toBeInTheDocument();
  });

  it("surfaces audit export problem+json errors", async () => {
    apiMock.auditEvents.mockResolvedValue([
      { sequence: 7, id: "evt-7", type: "identity.issued", tenant_id: "t1", time: "2026-06-17T12:00:00Z", hash: "abc" },
    ]);
    apiMock.exportAudit.mockRejectedValue(new ApiError(422, JSON.stringify({ detail: "audit export window too large" })));
    const user = userEvent.setup();
    renderAt("/audit");

    await screen.findByText("identity.issued");
    await user.click(screen.getByRole("button", { name: /Export evidence/i }));

    expect(await screen.findByText(/Could not export evidence: audit export window too large/)).toBeInTheDocument();
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
    const user = userEvent.setup();
    renderAt("/graph");

    expect(await screen.findByRole("heading", { name: "Graph" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /Graph/i })).toHaveAttribute("href", "/graph");
    expect((await screen.findAllByText("payments-cert")).length).toBeGreaterThan(0);

    await user.click(screen.getByRole("button", { name: /Analyze/i }));
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
    expect(screen.getByText("The credential is deployed to that workload or resource.")).toBeInTheDocument();

    await user.selectOptions(screen.getByLabelText("Kind"), "credential");
    expect(screen.getAllByTestId("graph-node-name").map((cell) => cell.textContent)).toEqual(["payments-cert"]);

    await user.click(screen.getByRole("button", { name: "Select payments-cert" }));

    expect(await screen.findByRole("heading", { name: "Node detail" })).toBeInTheDocument();
    expect(screen.getAllByText("cert:cert/unsafe").length).toBeGreaterThan(0);
    expect(screen.getByText("01")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Certificate detail" })).toHaveAttribute(
      "href",
      "/certificates?credential=cert%2Funsafe",
    );
    expect(screen.getByRole("link", { name: "Risk row" })).toHaveAttribute("href", "/risk?node=cert%3Acert%2Funsafe");
    expect(screen.getByRole("link", { name: "Audit evidence" })).toHaveAttribute(
      "href",
      "/audit?node=cert%3Acert%2Funsafe",
    );
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
    await user.click(screen.getByRole("button", { name: "Analyze" }));
    await waitFor(() => expect(apiMock.graphBlastRadius).toHaveBeenCalledWith("cert:payments"));
    expect(await screen.findByRole("heading", { name: "Blast-radius paths and by-kind summary" })).toBeInTheDocument();
    expect(screen.getAllByText("resource").length).toBeGreaterThan(0);
    expect(screen.getAllByText("payments-db").length).toBeGreaterThan(0);

    await user.click(screen.getByRole("button", { name: "Show reachable" }));
    await waitFor(() => expect(apiMock.graphReachable).toHaveBeenCalledWith("cert:payments"));
    expect(await screen.findByRole("heading", { name: "Reachable nodes" })).toBeInTheDocument();

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
    expect(screen.getByRole("button", { name: "Analyze" })).toBeDisabled();
    empty.unmount();

    apiMock.graph.mockRejectedValue(
      new ApiError(403, JSON.stringify({ detail: "tenant t2 graph scope exists but is forbidden" })),
    );
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
    apiMock.graphReachable.mockRejectedValue(new ApiError(429, "queue full", 7));
    apiMock.graphQuery.mockRejectedValue(new ApiError(422, JSON.stringify({ detail: "query parser rejected RETURN" })));
    const user = userEvent.setup();
    renderAt("/graph");

    await waitFor(() => expect(screen.getAllByTestId("graph-node-name")[0]).toHaveTextContent("payments-cert"));
    await user.click(screen.getByRole("button", { name: "Show reachable" }));
    expect(await screen.findByText(/Could not compute reachability: retry in 7s/)).toBeInTheDocument();

    await user.clear(screen.getByLabelText("Cypher-style query"));
    await user.type(screen.getByLabelText("Cypher-style query"), "RETURN");
    await user.click(screen.getByRole("button", { name: "Run graph query" }));
    expect(await screen.findByText(/Could not run graph query: query parser rejected RETURN/)).toBeInTheDocument();
  });

  it("routes to risk, expands all six served components, and sorts or filters by factor", async () => {
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
    const user = userEvent.setup();
    renderAt("/risk");

    expect(await screen.findByRole("heading", { name: "Credential risk" })).toBeInTheDocument();
    expect(screen.getAllByTestId("risk-subject").map((cell) => cell.textContent)).toEqual([
      "root-ca.example.test",
      "old-leaf.example.test",
    ]);

    const rootRow = screen.getByText("root-ca.example.test").closest("tr")!;
    await user.click(within(rootRow).getByRole("button", { name: /show factors/i }));
    for (const factor of ["age", "rotation", "privilege", "exposure", "owner", "sensitivity"]) {
      expect(screen.getByTestId(`risk-factor-${factor}`)).toBeInTheDocument();
    }
    expect(screen.getByTestId("risk-factor-exposure")).toHaveTextContent("95");

    await user.selectOptions(screen.getByLabelText("Sort by"), "age");
    await waitFor(() => expect(screen.getAllByTestId("risk-subject")[0]).toHaveTextContent("old-leaf.example.test"));

    await user.selectOptions(screen.getByLabelText("Focus factor"), "owner");
    await waitFor(() => expect(screen.getByText("root-ca.example.test")).toBeInTheDocument());
    expect(screen.queryByText("old-leaf.example.test")).not.toBeInTheDocument();
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

    expect(screen.getByRole("link", { name: "Credential detail" })).toHaveAttribute(
      "href",
      "/certificates?credential=cert%2Funsafe",
    );
    expect(screen.getByRole("link", { name: "Owner status orphaned" })).toHaveAttribute("href", "/owners?status=orphaned");
    expect(screen.getByRole("link", { name: "Graph blast radius" })).toHaveAttribute(
      "href",
      "/graph?node=cert%3Acert%2Funsafe",
    );
    expect(screen.getByRole("link", { name: "Audit evidence" })).toHaveAttribute(
      "href",
      "/audit?credential=cert%2Funsafe",
    );
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
    expect(screen.getAllByText(/BACKEND-RISK-ALLKINDS/).length).toBeGreaterThan(0);
    expect(screen.getByText(/1 non-certificate risk record is waiting/i)).toBeInTheDocument();
    expect(screen.queryByText("ssh-key-prod")).not.toBeInTheDocument();
    expect(screen.getByText(/No certificate risk scores match/i)).toBeInTheDocument();
  });
});

function riskRow(overrides: Partial<ReturnType<typeof riskRowBase>> = {}) {
  return { ...riskRowBase(), ...overrides, components: { ...riskRowBase().components, ...overrides.components } };
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
