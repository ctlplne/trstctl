import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { api } from "@/lib/api";

let fetchMock: ReturnType<typeof vi.fn>;

beforeEach(() => {
  fetchMock = vi.fn(async () => new Response("{}", { status: 200, headers: { "content-type": "application/json" } }));
  vi.stubGlobal("fetch", fetchMock);
});
afterEach(() => vi.unstubAllGlobals());

describe("U2-7 secret rotation served wiring", () => {
  it("rotates a secret via PUT against the served store path", async () => {
    await api.rotateSecret("prod/db/password", { value: "new-value" });
    const [url, init] = fetchMock.mock.calls[0];
    expect(String(url)).toContain("/api/v1/secrets/store/");
    expect((init as RequestInit).method).toBe("PUT");
  });
});
