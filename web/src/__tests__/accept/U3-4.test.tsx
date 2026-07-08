import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

vi.mock("@/lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/api")>();
  return {
    ...actual,
    api: {
      ...actual.api,
      graphBlastRadius: vi.fn(async () => ({
        node: { id: "n1", kind: "ca", name: "Root CA" },
        affected: [{ id: "a1", kind: "x509", name: "leaf.example" }],
        by_kind: {},
      })),
    },
  };
});

import { BlastRadiusExplorer } from "@/components/graph";
import type { GraphNode } from "@/lib/api";

const nodes = [{ id: "n1", kind: "ca", name: "Root CA" }] as unknown as GraphNode[];

describe("U3-4 blast radius explorer", () => {
  it("shows affected credentials for a selected node", async () => {
    render(<BlastRadiusExplorer nodes={nodes} />);
    await userEvent.selectOptions(screen.getByRole("combobox", { name: "Credential" }), "n1");
    expect(await screen.findByText(/1 affected credentials/)).toBeInTheDocument();
    expect(screen.getByText("leaf.example")).toBeInTheDocument();
  });
});
