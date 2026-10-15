import { afterEach, describe, expect, it, vi } from "vitest";
import { api } from "@/lib/api";

describe("ownership CSV transport", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("sends exact CSV bytes with a stable caller key and CSV media type", async () => {
    const response = { applied: 1, unchanged: 0, conflicts: [], detail: "", guidance: "" };
    const fetch = vi.fn().mockResolvedValue(new Response(JSON.stringify(response), { status: 200 }));
    vi.stubGlobal("fetch", fetch);
    const csv = "owner,service,source_ref\nPlatform team,new-service,qa-row\n";

    expect(await api.importOwnership(csv, "reviewed-qa-import-1")).toEqual(response);
    expect(fetch).toHaveBeenCalledWith(
      "/api/v1/owners/import",
      expect.objectContaining({
        method: "POST",
        body: csv,
        headers: expect.objectContaining({ "Content-Type": "text/csv", "Idempotency-Key": "reviewed-qa-import-1" }),
      }),
    );
  });
});
