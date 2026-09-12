import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { Graph } from "@/pages/Graph";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    graph: vi.fn(),
    graphBlastRadius: vi.fn(),
    graphReachable: vi.fn(),
    graphQuery: vi.fn(),
    graphTrustStores: vi.fn(),
  },
}));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...apiMock } };
});

function renderGraph(path = "/graph") {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <Graph />
    </MemoryRouter>,
  );
}

describe("route 027 impact-first graph design", () => {
  it("analyzes the exact deep-linked certificate instead of the default credential", async () => {
    apiMock.graph.mockResolvedValue({
      nodes: [
        { id: "cert:other", kind: "credential", name: "Other certificate" },
        { id: "cert:payments", kind: "credential", name: "Payments certificate" },
      ],
      edges: [],
    });
    renderGraph("/graph?node=cert%3Apayments");
    const picker = await screen.findByRole("combobox", { name: "Credential to explore" });
    await waitFor(() => expect(picker).toHaveValue("cert:payments"));
    await userEvent.setup().click(screen.getByRole("button", { name: "Explore impact" }));
    expect(apiMock.graphBlastRadius).toHaveBeenCalledWith("cert:payments");
    expect(apiMock.graphReachable).toHaveBeenCalledWith("cert:payments");
    await userEvent.setup().selectOptions(picker, "cert:other");
    expect(picker).toHaveValue("cert:other");
  });
  it("keeps a missing deep link explicit rather than selecting another credential", async () => {
    renderGraph("/graph?node=cert%3Amissing");
    const picker = await screen.findByRole("combobox", { name: "Credential to explore" });
    await waitFor(() => expect(picker).toHaveValue("cert:missing"));
    expect(apiMock.graphBlastRadius).not.toHaveBeenCalled();
  });
  beforeEach(() => {
    vi.restoreAllMocks();
    for (const mock of Object.values(apiMock)) mock.mockReset();
    apiMock.graph.mockResolvedValue({
      nodes: [
        { id: "cert:payments", kind: "credential", name: "payments-cert", attrs: { serial: "01", source_id: "source-7" } },
        { id: "res:db", kind: "resource", name: "payments-db", attrs: { environment: "production" } },
      ],
      edges: [
        {
          from: "cert:payments",
          to: "res:db",
          type: "GRANTS_ACCESS",
          source: "discovery source source-7",
          confidence: "observed",
        },
      ],
    });
    apiMock.graphBlastRadius.mockResolvedValue({
      node: { id: "cert:payments", kind: "credential", name: "payments-cert" },
      affected: [{ id: "res:db", kind: "resource", name: "payments-db" }],
      by_kind: { resource: 1 },
      paths: [
        {
          target: { id: "res:db", kind: "resource", name: "payments-db" },
          nodes: [
            { id: "cert:payments", kind: "credential", name: "payments-cert" },
            { id: "res:db", kind: "resource", name: "payments-db" },
          ],
          edges: [
            {
              from: "cert:payments",
              to: "res:db",
              type: "GRANTS_ACCESS",
              source: "discovery source source-7",
              confidence: "observed",
            },
          ],
        },
      ],
    });
    apiMock.graphReachable.mockResolvedValue({
      from: "cert:payments",
      nodes: [{ id: "res:db", kind: "resource", name: "payments-db" }],
      paths: [
        {
          target: { id: "res:db", kind: "resource", name: "payments-db" },
          nodes: [
            { id: "cert:payments", kind: "credential", name: "payments-cert" },
            { id: "res:db", kind: "resource", name: "payments-db" },
          ],
          edges: [{ from: "cert:payments", to: "res:db", type: "GRANTS_ACCESS", source: "discovery source source-7", confidence: "observed" }],
        },
      ],
    });
    apiMock.graphQuery.mockResolvedValue({ rows: [{ credential: "payments-cert", resource: "payments-db" }] });
    apiMock.graphTrustStores.mockResolvedValue({
      issuer: "",
      stores: [],
      hosts: [],
      store_count: 0,
      host_count: 0,
      candidate_stores: [],
      candidate_hosts: [],
      candidate_store_count: 0,
      candidate_host_count: 0,
      guidance: "",
    });
  });

  it("answers the impact question before revealing exact graph machinery", async () => {
    const user = userEvent.setup();
    renderGraph();

    expect(await screen.findByRole("heading", { level: 1, name: "What could be affected" })).toBeInTheDocument();
    expect(screen.getByText("Which systems depend on a selected credential.", { exact: true })).toBeInTheDocument();
    const credentialSelector = screen.getByLabelText("Credential to explore");
    await waitFor(() => expect(credentialSelector).toHaveValue("cert:payments"));
    expect(credentialSelector).toHaveClass("min-w-0", "max-w-full", "overflow-hidden", "text-ellipsis");
    expect(credentialSelector.closest("label")).toHaveClass("min-w-0", "max-w-full");
    expect(credentialSelector.closest("label")?.parentElement).toHaveClass("grid-cols-[minmax(0,1fr)]");
    expect(within(credentialSelector).getAllByRole("option")).toHaveLength(1);
    expect(within(credentialSelector).queryByRole("option", { name: /payments-db/ })).not.toBeInTheDocument();

    const operate = screen.getByTestId("page-depth-operate");
    expect(within(operate).getAllByRole("button")).toHaveLength(1);
    const explore = within(operate).getByRole("button", { name: "Explore impact" });
    expect(explore).toBeEnabled();

    const map = screen.getByText("Relationship map and filters", { exact: true }).closest("details");
    const evidence = screen.getByText("Graph edges, sources, confidence, and blast-radius export", { exact: true }).closest("details");
    const inventory = screen.getByText("Node inventory, exact attributes, and advanced query", { exact: true }).closest("details");
    expect(map).not.toHaveAttribute("open");
    expect(evidence).not.toHaveAttribute("open");
    expect(inventory).not.toHaveAttribute("open");
    expect(screen.queryByTestId("graph-visualization")).not.toBeInTheDocument();
    expect(screen.queryByRole("table")).not.toBeInTheDocument();
    expect(screen.queryByText("cert:payments", { exact: true })).not.toBeInTheDocument();

    await user.click(explore);
    await waitFor(() => expect(apiMock.graphBlastRadius).toHaveBeenCalledWith("cert:payments"));
    expect(apiMock.graphReachable).toHaveBeenCalledWith("cert:payments");
    expect(await screen.findByRole("heading", { name: "1 known system could be affected" })).toBeInTheDocument();
    expect(screen.getByText("payments-db", { exact: true })).toBeInTheDocument();
    expect(screen.getByText(/Only relationships currently known to trstctl are counted/)).toBeInTheDocument();

    await user.click(screen.getByText("Graph edges, sources, confidence, and blast-radius export", { exact: true }));
    expect(screen.getByText("discovery source source-7", { exact: true })).toBeInTheDocument();
    expect(screen.getByText("Observed", { exact: true })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Why these systems are connected" })).toBeInTheDocument();
    const paths = screen.getByTestId("graph-relationship-paths");
    expect(within(paths).getByText("payments-cert", { exact: true })).toBeInTheDocument();
    expect(within(paths).getByText("Grants access", { exact: true })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Open payments-db in risk" })).toHaveAttribute("href", "/risk?node=res%3Adb");
    expect(screen.getByRole("link", { name: "Open payments-db lifecycle" })).toHaveAttribute("href", "/identities?node=res%3Adb");
    expect(screen.getByRole("link", { name: "Open payments-db audit evidence" })).toHaveAttribute("href", "/audit?node=res%3Adb");
    expect(screen.getByRole("link", { name: "Export blast-radius evidence" })).toHaveAttribute("download", "blast-radius-payments-cert.json");
    const exported = decodeURIComponent(screen.getByRole("link", { name: "Export blast-radius evidence" }).getAttribute("href") ?? "");
    expect(exported).toContain('"paths"');
    expect(exported).toContain('"GRANTS_ACCESS"');

    await user.click(screen.getByText("Relationship map and filters", { exact: true }));
    expect(screen.getByTestId("graph-visualization")).toBeInTheDocument();

    await user.click(screen.getByText("Node inventory, exact attributes, and advanced query", { exact: true }));
    expect(screen.getByLabelText("Search")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Run graph query" })).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Select payments-db" }));
    expect(credentialSelector).toHaveValue("cert:payments");
  });

  it("renders a truthful zero-impact answer when an older server sends null arrays", async () => {
    apiMock.graph.mockResolvedValue({
      nodes: [{ id: "cert:leaf", kind: "credential", name: "new-leaf", attrs: {} }],
      edges: [],
    });
    apiMock.graphBlastRadius.mockResolvedValue({
      node: { id: "cert:leaf", kind: "credential", name: "new-leaf" },
      affected: null,
      by_kind: null,
      paths: null,
    });
    apiMock.graphReachable.mockResolvedValue({ from: "cert:leaf", nodes: [] });
    const user = userEvent.setup();

    renderGraph();
    await user.click(await screen.findByRole("button", { name: "Explore impact" }));

    expect(await screen.findByRole("heading", { name: "0 known systems could be affected" })).toBeInTheDocument();
    expect(screen.getByText(/Only relationships currently known to trstctl are counted/)).toBeInTheDocument();
  });
});
