import { afterEach, describe, expect, it, vi } from "vitest";
import { api } from "@/lib/api";

function owner(id: string, name: string) {
  return { id, tenant_id: "qa-tenant", kind: "team", name };
}

describe("owner directory pagination", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("loads a newly created owner beyond the first page for the console and owner selectors", async () => {
    const fetch = vi
      .fn()
      .mockResolvedValueOnce(Response.json({ items: [owner("old", "Existing owner")], next_cursor: "next-owner-page" }))
      .mockResolvedValueOnce(Response.json({ items: [owner("new", "QA owner to remove")], next_cursor: "" }));
    vi.stubGlobal("fetch", fetch);

    await expect(api.owners()).resolves.toEqual([owner("old", "Existing owner"), owner("new", "QA owner to remove")]);
    expect(fetch).toHaveBeenNthCalledWith(1, "/api/v1/owners?limit=100", expect.any(Object));
    expect(fetch).toHaveBeenNthCalledWith(2, "/api/v1/owners?limit=100&cursor=next-owner-page", expect.any(Object));
  });

  it("refuses a repeated cursor instead of showing a partial owner directory", async () => {
    const fetch = vi.fn().mockImplementation(async () => Response.json({ items: [owner("old", "Existing owner")], next_cursor: "loop" }));
    vi.stubGlobal("fetch", fetch);

    await expect(api.owners()).rejects.toThrow(/repeated cursor/);
    expect(fetch).toHaveBeenCalledTimes(2);
  });
});
