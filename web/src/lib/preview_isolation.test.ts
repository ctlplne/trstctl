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

  it("serves the eight evaluation routes from deterministic browser fixtures without fetch", async () => {
    const fetchSpy = vi.fn();
    vi.stubGlobal("fetch", fetchSpy);
    setPreviewTransportIsolation(true);

    const firstCertificates = await api.certificates();
    firstCertificates[0]!.subject = "mutated by test";

    await expect(api.certificates()).resolves.toEqual(expect.arrayContaining([expect.objectContaining({ subject: "api.preview-lab.example" })]));
    await expect(api.certificatePage()).resolves.toEqual(
      expect.objectContaining({ items: expect.arrayContaining([expect.objectContaining({ subject: "api.preview-lab.example" })]) }),
    );
    await expect(api.listCBOMAssets()).resolves.toEqual(
      expect.objectContaining({ items: expect.arrayContaining([expect.objectContaining({ location: "edge.preview-lab.example:443" })]) }),
    );
    await expect(api.risk({ sort: "score" })).resolves.toEqual(
      expect.arrayContaining([expect.objectContaining({ subject: "api.preview-lab.example", score: 94 })]),
    );
    await expect(api.secretPage({ limit: 20 })).resolves.toEqual(
      expect.objectContaining({ items: expect.arrayContaining([expect.objectContaining({ name: "payments/production/database" })]) }),
    );
    await expect(api.sshFleet()).resolves.toEqual(
      expect.objectContaining({ hosts: expect.arrayContaining([expect.objectContaining({ location: "bastion.preview-lab.example" })]) }),
    );
    await expect(api.incidentExecutions({ limit: 10 })).resolves.toEqual(
      expect.objectContaining({ items: expect.arrayContaining([expect.objectContaining({ id: "incident-preview-001" })]) }),
    );
    await expect(api.caAuthorities()).resolves.toEqual(
      expect.objectContaining({ items: expect.arrayContaining([expect.objectContaining({ common_name: "Preview Lab Root CA" })]) }),
    );
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("keeps mutations and non-fixture session calls disabled before fetch", async () => {
    const fetchSpy = vi.fn();
    vi.stubGlobal("fetch", fetchSpy);
    setPreviewTransportIsolation(true);

    await expect(api.createSecret({ name: "blocked", value: "never sent" })).rejects.toBeInstanceOf(ApiError);
    await expect(api.me()).rejects.toThrowError(/browser demo/);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("restores normal transport when isolation lifts", async () => {
    const fetchSpy = vi.fn().mockResolvedValue(new Response(JSON.stringify([]), { status: 200, headers: { "Content-Type": "application/json" } }));
    vi.stubGlobal("fetch", fetchSpy);

    setPreviewTransportIsolation(true);
    await expect(api.certificates()).resolves.toHaveLength(3);
    setPreviewTransportIsolation(false);
    await expect(api.certificates()).resolves.toEqual([]);
    expect(fetchSpy).toHaveBeenCalledTimes(1);
  });
});
