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

function renderGraph() {
  return render(
    <MemoryRouter>
      <Graph />
    </MemoryRouter>,
  );
}

describe("route 027 impact-first graph design", () => {
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
    });
    apiMock.graphReachable.mockResolvedValue({
      from: "cert:payments",
      nodes: [{ id: "res:db", kind: "resource", name: "payments-db" }],
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
    expect(credentialSelector).toHaveClass("min-w-0", "max-w-full");
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
    expect(screen.getByRole("link", { name: "Export blast-radius evidence" })).toHaveAttribute("download", "blast-radius-payments-cert.json");

    await user.click(screen.getByText("Relationship map and filters", { exact: true }));
    expect(screen.getByTestId("graph-visualization")).toBeInTheDocument();

    await user.click(screen.getByText("Node inventory, exact attributes, and advanced query", { exact: true }));
    expect(screen.getByLabelText("Search")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Run graph query" })).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Select payments-db" }));
    expect(credentialSelector).toHaveValue("cert:payments");
  });
});
