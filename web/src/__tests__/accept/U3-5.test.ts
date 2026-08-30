import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { api } from "@/lib/api";

let fetchMock: ReturnType<typeof vi.fn>;

beforeEach(() => {
  fetchMock = vi.fn(async () => new Response("{}", { status: 200, headers: { "content-type": "application/json" } }));
  vi.stubGlobal("fetch", fetchMock);
});
afterEach(() => vi.unstubAllGlobals());

describe("U3-5 workload + agent broker served wiring", () => {
  it("previews without mutation headers and preserves the caller's exact issuance retry key", async () => {
    const input = { method: "k8s_sat" as const, payload_base64: "c2F0", public_key_pem: "public-key", ttl_seconds: 600 };
    await api.previewAttestedSVID(input);
    const [url, options] = fetchMock.mock.calls.at(-1)! as [string, RequestInit];
    expect(String(url)).toContain("/api/v1/workloads/attested-issuance/preview");
    expect(new Headers(options.headers).get("Idempotency-Key")).toBeNull();
    expect(JSON.parse(String(options.body))).toEqual(input);
    await api.issueAttestedSVID(input, "attested-exact-retry");
    const issuance = fetchMock.mock.calls.at(-1)! as [string, RequestInit];
    expect(new Headers(issuance[1].headers).get("Idempotency-Key")).toBe("attested-exact-retry");
  });

  it("issues attested SVIDs, broker identities, and ephemeral keys against served endpoints", async () => {
    await api.issueBrokerAgentIdentity(undefined as never);
    expect(String(fetchMock.mock.calls[0][0])).toContain("/api/v1/broker/agent-identities");
    await api.issueAttestedSVID(undefined as never);
    expect(String(fetchMock.mock.calls.at(-1)?.[0])).toContain("/api/v1/workloads/attested-issuance");
    await api.issueEphemeralAPIKey(undefined as never);
    expect(String(fetchMock.mock.calls.at(-1)?.[0])).toContain("/api/v1/ephemeral/api-keys");
  });
});
