import { afterEach, describe, expect, it, vi } from "vitest";
import { api, ApiError, setPreviewTransportIsolation } from "@/lib/api";

/** Demo-site safety contract (mirrors probectl's transport isolation): while
 * preview is active the client refuses every server call BEFORE fetch, so a
 * statically hosted demo bundle can never emit a network request. The demo
 * Worker's /api/* 404s are belt-and-suspenders; this is the wall. */
describe("preview transport isolation", () => {
  afterEach(() => {
    setPreviewTransportIsolation(false);
    vi.unstubAllGlobals();
  });

  it("refuses tenant API calls before fetch while isolated", async () => {
    const fetchSpy = vi.fn();
    vi.stubGlobal("fetch", fetchSpy);
    setPreviewTransportIsolation(true);

    await expect(api.certificates()).rejects.toBeInstanceOf(ApiError);
    await expect(api.me()).rejects.toThrowError(/browser demo/);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("restores normal transport when isolation lifts", async () => {
    const fetchSpy = vi.fn().mockResolvedValue(new Response(JSON.stringify([]), { status: 200, headers: { "Content-Type": "application/json" } }));
    vi.stubGlobal("fetch", fetchSpy);

    setPreviewTransportIsolation(true);
    await expect(api.certificates()).rejects.toBeInstanceOf(ApiError);
    setPreviewTransportIsolation(false);
    await expect(api.certificates()).resolves.toEqual([]);
    expect(fetchSpy).toHaveBeenCalledTimes(1);
  });
});
