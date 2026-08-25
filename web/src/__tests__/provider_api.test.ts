// SPDX-License-Identifier: MPL-2.0

import { afterEach, describe, expect, it, vi } from "vitest";
import { providerApi } from "@/lib/providerApi";

describe("Provider public attachment preflight", () => {
  afterEach(() => vi.unstubAllGlobals());

  it.each([
    [true, true],
    [false, false],
  ])("returns the exact boolean attachment state %s", async (wire, expected) => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ oidc: true, saml: false, ldap: false, provider_plane: wire }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );
    vi.stubGlobal("fetch", fetchMock);

    await expect(providerApi.availability()).resolves.toBe(expected);
    expect(fetchMock).toHaveBeenCalledWith("/auth/methods", {
      credentials: "same-origin",
      headers: { Accept: "application/json" },
    });
  });

  it.each([
    ["missing field", new Response(JSON.stringify({ oidc: true }), { status: 200 })],
    ["wrong field type", new Response(JSON.stringify({ provider_plane: "yes" }), { status: 200 })],
    ["non-success response", new Response("unavailable", { status: 503 })],
  ])("returns unknown for %s", async (_name, response) => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(response));
    await expect(providerApi.availability()).resolves.toBeNull();
  });

  it("returns unknown when the bootstrap request cannot be completed", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("network unavailable")));
    await expect(providerApi.availability()).resolves.toBeNull();
  });
});
