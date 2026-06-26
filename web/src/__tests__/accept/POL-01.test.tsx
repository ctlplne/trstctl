import { readFileSync } from "node:fs";
import path from "node:path";
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

describe("POL-01 graph polish", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    for (const mock of Object.values(apiMock)) mock.mockReset();
    apiMock.graph.mockResolvedValue({
      nodes: [
        { id: "cert:payments", kind: "credential", name: "payments-cert", attrs: { serial: "01" } },
        { id: "workload:payments", kind: "workload", name: "payments-api", attrs: { owner: "team-a" } },
      ],
      edges: [{ from: "cert:payments", to: "workload:payments", type: "DEPLOYED_TO" }],
    });
    apiMock.graphBlastRadius.mockResolvedValue({
      node: { id: "cert:payments", kind: "credential", name: "payments-cert" },
      affected: [{ id: "workload:payments", kind: "workload", name: "payments-api" }],
      by_kind: { workload: 1 },
    });
    apiMock.graphReachable.mockResolvedValue({
      from: "cert:payments",
      nodes: [{ id: "workload:payments", kind: "workload", name: "payments-api" }],
    });
    apiMock.graphQuery.mockResolvedValue({ rows: [{ credential: "payments-cert", workload: "payments-api" }] });
  });

  it("keeps query controls behind an advanced tab and renders node choices as a list", async () => {
    const user = userEvent.setup();
    renderGraph();

    expect(await screen.findByRole("heading", { name: "Graph" })).toBeInTheDocument();
    expect((await screen.findAllByText("payments-cert")).length).toBeGreaterThan(0);
    expect(screen.queryByLabelText("Cypher-style query")).not.toBeInTheDocument();

    const nodeList = screen.getByRole("list", { name: "Node search results" });
    expect(within(nodeList).getByText("payments-cert")).toBeInTheDocument();
    expect(within(nodeList).getByText("payments-api")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Choose payments-cert" })).not.toBeInTheDocument();

    await user.clear(screen.getByLabelText("Search"));
    await user.type(screen.getByLabelText("Search"), "payments-api");
    expect(within(screen.getByRole("list", { name: "Node search results" })).queryByText("payments-cert")).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Select graph node payments-api" }));
    expect(screen.getByRole("heading", { name: "Node detail" })).toBeInTheDocument();
    expect(screen.getAllByText("workload:payments").length).toBeGreaterThan(0);

    await user.clear(screen.getByLabelText("Search"));
    await user.click(screen.getByRole("button", { name: "Select graph node payments-cert" }));
    await user.click(screen.getByRole("button", { name: "Analyze selected node" }));

    await waitFor(() => expect(apiMock.graphBlastRadius).toHaveBeenCalledWith("cert:payments"));
    expect(apiMock.graphReachable).toHaveBeenCalledWith("cert:payments");
    expect(await screen.findByRole("heading", { name: "Reachable nodes" })).toBeInTheDocument();

    await user.click(screen.getByRole("tab", { name: "Advanced query" }));
    expect(screen.getByLabelText("Cypher-style query")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Run graph query" }));

    await waitFor(() => expect(apiMock.graphQuery).toHaveBeenCalledWith("MATCH (a)-[e]->(b) RETURN a,b"));
    expect(await screen.findByRole("link", { name: "Export query rows" })).toHaveAttribute("download", "graph-query-results.json");
  });

  it("removes the old query placement and chooser wall from the module", () => {
    const source = readFileSync(path.join(process.cwd(), "src/pages/Graph.tsx"), "utf8");
    expect(source).not.toMatch(/Choose \{node\.name|Show reachable/);
    expect(source).toMatch(/Advanced query/);
    expect(source).toMatch(/Node search results/);
  });
});
