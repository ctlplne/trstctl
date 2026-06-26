import { describe, it, expect, vi } from "vitest";
import { searchInventory, type SearchClient } from "@/lib/search";

function client(): SearchClient {
  return {
    certificatePage: vi.fn().mockResolvedValue({ items: [] }),
    identities: vi.fn().mockResolvedValue([]),
    secretPage: vi.fn().mockResolvedValue({ items: [] }),
    agents: vi.fn().mockResolvedValue([{ id: "a1", name: "edge-agent", status: "online", version: "2.0.0" }]),
  };
}

describe("U0-5 global search across credential types", () => {
  it("includes agents as a searchable credential type", async () => {
    const response = await searchInventory("edge", client());
    expect(response.unavailableSources).toEqual([]);
    expect(response.results).toEqual([expect.objectContaining({ kind: "agent", label: "edge-agent", to: "/agents" })]);
  });
});
