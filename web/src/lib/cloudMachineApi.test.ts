import { beforeEach, describe, expect, it, vi } from "vitest";
import { loadCloudReplacementChoices } from "./cloudMachineApi";
import { req } from "./apiTransport";
vi.mock("./apiTransport", () => ({ req: vi.fn(), mutate: vi.fn() }));
const role = (id: string, at: string, native = true) => ({
  id,
  metadata: {
    ...(native ? { source_origin: "https://iam.amazonaws.com" } : {}),
    collected_at: at,
    identity: { native_id: "AROAOWNED", principal: { arn: "arn:aws:iam::111122223333:role/orders" } },
  },
});
describe("bounded replacement source choices", () => {
  beforeEach(() => vi.mocked(req).mockReset());
  it("reads all pages and uses the latest native role capture with ready STS providers", async () => {
    vi.mocked(req)
      .mockResolvedValueOnce({
        configured_providers: [
          { id: "ready", type: "aws-sts", ready: true, maximum_ttl_seconds: 900 },
          { id: "disabled", type: "aws-sts", ready: false, maximum_ttl_seconds: 900 },
          { id: "other", type: "aws-iam", ready: true, maximum_ttl_seconds: 3600 },
        ],
      })
      .mockResolvedValueOnce({ items: [role("old", "2026-11-05T00:00:00Z"), role("recorded", "2026-11-07T00:00:00Z", false)], next_cursor: "page2" })
      .mockResolvedValueOnce({ items: [role("new", "2026-11-06T00:00:00Z")], next_cursor: "" });
    const abort = new AbortController();
    const choices = await loadCloudReplacementChoices(abort.signal);
    expect(choices.providers.map((p) => p.id)).toEqual(["ready"]);
    expect(choices.roles.map((r) => r.id)).toEqual(["new"]);
    expect(req).toHaveBeenNthCalledWith(3, expect.stringContaining("cursor=page2"), { signal: abort.signal });
  });
  it("refuses to present a partial catalog as complete", async () => {
    vi.mocked(req).mockResolvedValueOnce({ configured_providers: [] }).mockResolvedValue({ items: [], next_cursor: "more" });
    await expect(loadCloudReplacementChoices()).rejects.toThrow("cloud_replacement_catalog_limit");
    expect(req).toHaveBeenCalledTimes(11);
  });
});
