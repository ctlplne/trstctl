import { describe, expect, it, vi } from "vitest";
import { searchInventory, type SearchClient } from "@/lib/search";

const certificate = {
  id: "cert-1",
  subject: "payments-api",
  fingerprint: "SHA256:abc123",
  status: "active",
  tenant_id: "t1",
} as const;

const identity = {
  id: "id-1",
  kind: "workload_identity",
  name: "payments-worker",
  owner_id: "owner-1",
  status: "issued",
  tenant_id: "t1",
} as const;

const secret = {
  name: "payments/db/password",
  version: 3,
} as const;

const agent = {
  id: "agent-1",
  name: "payments-agent",
  status: "online",
  version: "1.4.0",
} as const;

function client(overrides: Partial<SearchClient> = {}): SearchClient {
  return {
    certificatePage: vi.fn().mockResolvedValue({ items: [certificate] }),
    identities: vi.fn().mockResolvedValue([identity]),
    secretPage: vi.fn().mockResolvedValue({ items: [secret] }),
    agents: vi.fn().mockResolvedValue([agent]),
    ...overrides,
  };
}

describe("global inventory search", () => {
  it("merges served certificate, identity, secret, and agent metadata results", async () => {
    const response = await searchInventory("payments", client());

    expect(response.unavailableSources).toEqual([]);
    expect(response.results).toEqual([
      expect.objectContaining({ kind: "certificate", label: "payments-api", to: "/certificates" }),
      expect.objectContaining({ kind: "identity", label: "payments-worker", to: "/identities" }),
      expect.objectContaining({ kind: "secret", label: "payments/db/password", to: "/secrets" }),
      expect.objectContaining({ kind: "agent", label: "payments-agent", to: "/agents" }),
    ]);
  });

  it("does not query served lists for an empty query", async () => {
    const api = client();
    const response = await searchInventory("  ", api);

    expect(response.results).toEqual([]);
    expect(response.unavailableSources).toEqual([]);
    expect(api.certificatePage).not.toHaveBeenCalled();
    expect(api.identities).not.toHaveBeenCalled();
    expect(api.secretPage).not.toHaveBeenCalled();
    expect(api.agents).not.toHaveBeenCalled();
  });

  it("keeps healthy sources searchable when one served list fails", async () => {
    const response = await searchInventory(
      "payments",
      client({
        certificatePage: vi.fn().mockRejectedValue(new Error("certificates offline")),
      }),
    );

    expect(response.unavailableSources).toEqual(["certificates"]);
    expect(response.results.map((result) => result.kind)).toEqual(["identity", "secret", "agent"]);
  });
});
