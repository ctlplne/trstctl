import { describe, expect, it, vi } from "vitest";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { canonicalGraphEdgeTypes, graphEdgeTypeLabel, graphNodeKindLabel } from "@/components/GraphView";
import { PathFinder, WhoCanReach } from "@/pages/GraphAccess";

const { apiMock } = vi.hoisted(() => ({
  apiMock: { graphReachers: vi.fn(), graphPath: vi.fn() },
}));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...apiMock } };
});

const database = { id: "res:pam:postgres:pg-main", kind: "resource", name: "pg-main" };
const alice = { id: "person:alice", kind: "person", name: "Alice Example" };
const bob = { id: "person:bob", kind: "person", name: "Bob Reviewer" };
const session = { id: "pam:s1", kind: "credential", name: "readonly@pg-main" };
const workload = { id: "principal:spiffe://lab/pam", kind: "workload", name: "spiffe://lab/pam" };
const coverage = {
  sources: ["PAM sessions to databases and hosts, with the approvals they consumed"],
  not_covered: ["access granted outside trstctl"],
  note: "An empty or partial answer is not proof that nobody has access.",
};
const edge = (from: string, to: string, type: string, source: string) => ({ from, to, type, source, confidence: "authoritative" });

describe("G1 who can reach", () => {
  it("names the new node kinds", () => {
    expect(graphNodeKindLabel("person")).toBe("Person");
    expect(graphNodeKindLabel("role")).toBe("Role");
    expect(graphNodeKindLabel("ai-agent")).toBe("AI agent");
  });

  // G1-L4: who may read a secret scope, and the secrets a scope holds.
  it("names the secret store's read and containment links", () => {
    expect(graphEdgeTypeLabel("CAN_READ")).toBe("Can read");
    expect(graphEdgeTypeLabel("CONTAINS")).toBe("Contains");
    expect(canonicalGraphEdgeTypes).toEqual(expect.arrayContaining(["CAN_READ", "CONTAINS"]));
  });

  // A172-L3: a private key found in a secret store links to its certificate.
  it("names the link from a stored private key to its certificate", () => {
    expect(graphEdgeTypeLabel("KEY_OF")).toBe("Key of");
    expect(canonicalGraphEdgeTypes).toContain("KEY_OF");
  });

  it("shows each credential with its holders and approvers and the record behind every link", async () => {
    const grant = edge(session.id, database.id, "GRANTS_ACCESS", "PAM session grant");
    apiMock.graphReachers.mockResolvedValue({
      target: database,
      reachers: [alice, session, workload],
      by_kind: {},
      paths: [],
      access: [
        {
          credential: session,
          grant,
          path: { target: database, nodes: [session, database], edges: [grant] },
          holders: [
            { node: alice, edge: edge(alice.id, session.id, "HOLDS", "PAM session requester") },
            { node: workload, edge: edge(workload.id, session.id, "HOLDS", "PAM session attested workload") },
          ],
          approvers: [{ node: bob, edge: edge(bob.id, session.id, "APPROVED", "PAM approval decision") }],
        },
      ],
      coverage,
    });
    const user = userEvent.setup();
    render(<WhoCanReach nodes={[alice, database, session]} />);
    await user.selectOptions(screen.getByRole("combobox", { name: "Database, host or node" }), database.id);
    await user.click(screen.getByRole("button", { name: "Show who can reach it" }));
    expect(apiMock.graphReachers).toHaveBeenCalledWith(database.id);
    const answer = within((await screen.findByRole("heading", { name: "1 credential reaches pg-main" })).parentElement!);
    expect(answer.getByText("Credential: readonly@pg-main · Credential")).toBeInTheDocument();
    expect(answer.getByText("Grants access · PAM session grant · authoritative")).toBeInTheDocument();
    expect(answer.getByText("Alice Example · Person")).toBeInTheDocument();
    expect(answer.getByText("Holds · PAM session requester · authoritative")).toBeInTheDocument();
    expect(answer.getByText("Holds · PAM session attested workload · authoritative")).toBeInTheDocument();
    expect(answer.getByText("Bob Reviewer · Person")).toBeInTheDocument();
    expect(answer.getByText("Approved · PAM approval decision · authoritative")).toBeInTheDocument();
    expect(answer.getByText(coverage.note)).toBeInTheDocument();
  });

  it("never reads an empty answer as nobody: it states what is not covered", async () => {
    apiMock.graphReachers.mockResolvedValue({ target: database, reachers: [], by_kind: {}, paths: [], access: [], coverage });
    const user = userEvent.setup();
    render(<WhoCanReach nodes={[database]} />);
    await user.selectOptions(screen.getByRole("combobox", { name: "Database, host or node" }), database.id);
    await user.click(screen.getByRole("button", { name: "Show who can reach it" }));
    expect(await screen.findByRole("heading", { name: "No access grant in trstctl's records reaches pg-main" })).toBeInTheDocument();
    expect(screen.getByText("Not covered: access granted outside trstctl")).toBeInTheDocument();
  });

  it("shows a path hop by hop, and the server's reason when there is none", async () => {
    const holds = edge(alice.id, session.id, "HOLDS", "PAM session requester");
    const grant = edge(session.id, database.id, "GRANTS_ACCESS", "PAM session grant");
    apiMock.graphPath.mockResolvedValueOnce({
      from: alice.id,
      to: database.id,
      path: { target: database, nodes: [alice, session, database], edges: [holds, grant] },
    });
    apiMock.graphPath.mockRejectedValueOnce(new Error("no path from person:bob to res:pam:postgres:pg-main"));
    const user = userEvent.setup();
    render(<PathFinder nodes={[alice, bob, database]} />);
    await user.selectOptions(screen.getByRole("combobox", { name: "From" }), alice.id);
    await user.selectOptions(screen.getByRole("combobox", { name: "To" }), database.id);
    await user.click(screen.getByRole("button", { name: "Show the path" }));
    expect(apiMock.graphPath).toHaveBeenCalledWith(alice.id, database.id);
    const path = await screen.findByRole("list", { name: "How does one node reach another?" });
    expect(path).toHaveTextContent("Alice Example · Person");
    expect(path).toHaveTextContent("Holds · PAM session requester · authoritative");
    expect(path).toHaveTextContent("Grants access · PAM session grant · authoritative");

    await user.selectOptions(screen.getByRole("combobox", { name: "From" }), bob.id);
    await user.click(screen.getByRole("button", { name: "Show the path" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Could not find a path: no path from person:bob to res:pam:postgres:pg-main");
  });
});
