import { afterEach, describe, expect, it, vi } from "vitest";
import { api, type AuditQuery } from "./api";
import { setPreviewTransportIsolation } from "./apiTransport";

const query: AuditQuery = {
  tool: "workloads_machines",
  featureID: "F30",
  action: "upsert_trust",
  type: "attestation.verified",
  q: "payments & invoicing",
  asOf: 12,
  since: "2026-08-30T00:00:00Z",
  until: "2026-08-31T00:00:00Z",
  limit: 2,
};

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  vi.useRealTimers();
  setPreviewTransportIsolation(false);
});

describe("one audit selector across every evidence encoding", () => {
  it("keeps tool, feature, action, text, time and as-of constraints identical", async () => {
    const fetchMock = vi.fn().mockImplementation(async () => new Response(JSON.stringify({ events: [], format: "jws", bundle: "sealed" })));
    vi.stubGlobal("fetch", fetchMock);
    const NativeURL = URL;
    const revoke = vi.fn();
    class DownloadURL extends NativeURL {
      static createObjectURL = vi.fn().mockReturnValue("blob:audit-fixture");
      static revokeObjectURL = revoke;
    }
    vi.stubGlobal("URL", DownloadURL);
    const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});
    await api.auditEvents(query);
    await api.exportAudit(query);
    for (const format of ["ndjson", "csv", "splunk-hec", "sentinel"]) await api.downloadAuditExport(query, format);
    const selectors = fetchMock.mock.calls.map(([path]) => {
      const params = new NativeURL(path, "http://localhost").searchParams;
      params.delete("format");
      return Object.fromEntries(params);
    });
    const expected = {
      tool: query.tool,
      feature_id: query.featureID,
      action: query.action,
      type: query.type,
      q: query.q,
      as_of: "12",
      since: query.since,
      until: query.until,
      limit: "2",
    };
    expect(selectors).toHaveLength(6);
    for (const selector of selectors) expect(selector).toEqual(expected);
    expect(click).toHaveBeenCalledTimes(4);
    expect(revoke).toHaveBeenCalledTimes(4);
  });

  it("cancels a stream without creating a download after the scope changes", async () => {
    const controller = new AbortController();
    const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});
    vi.stubGlobal(
      "fetch",
      vi.fn().mockImplementation(async () => {
        controller.abort();
        return new Response("old scope");
      }),
    );
    await expect(api.downloadAuditExport(query, "csv", controller.signal)).rejects.toThrow();
    expect(click).not.toHaveBeenCalled();
  });

  it("sets a 15-second cap and forwards audit and expiry cancellation to fetch", async () => {
    const timeout = vi.spyOn(AbortSignal, "timeout");
    const signals: AbortSignal[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn().mockImplementation(async (_path: string, init: RequestInit) => {
        signals.push(init.signal as AbortSignal);
        return new Response(JSON.stringify({ events: [] }));
      }),
    );
    const controller = new AbortController();
    await api.auditEvents(query, controller.signal);
    await api.certificateHealth(controller.signal);
    expect(timeout).toHaveBeenCalledTimes(2);
    expect(timeout).toHaveBeenNthCalledWith(1, 15_000);
    expect(timeout).toHaveBeenNthCalledWith(2, 15_000);
    expect(signals.every((signal) => !signal.aborted)).toBe(true);
    controller.abort();
    expect(signals.every((signal) => signal.aborted)).toBe(true);
  });

  it("downloads exact signed report bytes through the isolated same-origin transport", async () => {
    const signed = '{"manifest":{"run_id":"fixture"},"signature":"AQ=="}\n';
    const response = new Response(signed);
    const exactBody = new Blob([signed]);
    vi.spyOn(response, "blob").mockResolvedValue(exactBody);
    const fetchMock = vi.fn().mockResolvedValue(response);
    vi.stubGlobal("fetch", fetchMock);
    let saved: Blob | undefined;
    const NativeURL = URL;
    class DownloadURL extends NativeURL {
      static createObjectURL = vi.fn((blob: Blob) => {
        saved = blob;
        return "blob:report-fixture";
      });
      static revokeObjectURL = vi.fn();
    }
    vi.stubGlobal("URL", DownloadURL);
    const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});
    const id = "44444444-4444-4444-8444-444444444444";
    expect(await api.downloadScheduledReport(id)).toBe(`trstctl-report-${id}.json`);
    expect(fetchMock.mock.calls[0][0]).toBe(`/api/v1/compliance/report-runs/${id}/artifact`);
    expect(saved).toBe(exactBody);
    expect(click).toHaveBeenCalledOnce();
    expect(DownloadURL.revokeObjectURL).toHaveBeenCalledWith("blob:report-fixture");
    setPreviewTransportIsolation(true);
    await expect(api.downloadScheduledReport(id)).rejects.toThrow();
    expect(fetchMock).toHaveBeenCalledOnce();
  });
});
