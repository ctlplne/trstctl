import { afterEach, describe, expect, it, vi } from "vitest";
import { api, setPreviewTransportIsolation } from "@/lib/api";

describe("SCEP qualification transport", () => {
  afterEach(() => {
    setPreviewTransportIsolation(false);
    vi.restoreAllMocks();
  });

  it("proves capabilities, public CA material, and an empty-message refusal without credentials or a CSR", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
      const path = String(input);
      if (path.endsWith("GetCACaps")) {
        return new Response("Renewal\nPOSTPKIOperation\nSHA-256\nSCEPStandard\n", {
          status: 200,
          headers: { "Content-Type": "text/plain" },
        });
      }
      if (path.endsWith("GetCACert")) {
        return new Response(new Uint8Array([0x30, 0x03, 0x02, 0x01, 0x01]), {
          status: 200,
          headers: { "Content-Type": "application/x-x509-ca-cert" },
        });
      }
      if (path.endsWith("PKIOperation")) {
        return new Response("scep: empty PKIOperation body\n", {
          status: 400,
          headers: { "Content-Type": "text/plain" },
        });
      }
      throw new Error(`unexpected fetch ${path}`);
    });

    const result = await api.scepQualification();

    expect(result.passed).toBe(true);
    expect(result.checks.map((check) => [check.id, check.status_code, check.passed])).toEqual([
      ["capabilities", 200, true],
      ["ca-material", 200, true],
      ["empty-message-gate", 400, true],
    ]);
    expect(fetchMock).toHaveBeenCalledTimes(3);
    for (const [, init] of fetchMock.mock.calls) expect(init).toEqual(expect.objectContaining({ credentials: "omit" }));
    expect(fetchMock).toHaveBeenNthCalledWith(3, "/scep?operation=PKIOperation", expect.objectContaining({ method: "POST", credentials: "omit" }));
    const operationInit = fetchMock.mock.calls[2]?.[1] as RequestInit;
    expect(operationInit.body).toBeUndefined();
    expect(operationInit.headers).not.toMatchObject({ Authorization: expect.anything() });
  });

  it("fails closed when an empty PKIOperation is accepted", async () => {
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
      const path = String(input);
      if (path.endsWith("GetCACaps"))
        return new Response("POSTPKIOperation\nSHA-256\nSCEPStandard\n", { status: 200, headers: { "Content-Type": "text/plain" } });
      if (path.endsWith("GetCACert")) {
        return new Response(new Uint8Array([0x30, 0x03, 0x02, 0x01, 0x01]), {
          status: 200,
          headers: { "Content-Type": "application/x-x509-ca-cert" },
        });
      }
      return new Response(null, { status: 200 });
    });

    const result = await api.scepQualification();

    expect(result.passed).toBe(false);
    expect(result.checks.find((check) => check.id === "empty-message-gate")).toMatchObject({ passed: false, status_code: 200 });
  });

  it("rejects a response that only claims to be CA material", async () => {
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
      const path = String(input);
      if (path.endsWith("GetCACaps"))
        return new Response("POSTPKIOperation\nSHA-256\nSCEPStandard\n", { status: 200, headers: { "Content-Type": "text/plain" } });
      if (path.endsWith("GetCACert")) return new Response("not DER", { status: 200, headers: { "Content-Type": "application/x-x509-ca-cert" } });
      return new Response("scep: empty PKIOperation body\n", { status: 400, headers: { "Content-Type": "text/plain" } });
    });

    const result = await api.scepQualification();

    expect(result.passed).toBe(false);
    expect(result.checks.find((check) => check.id === "ca-material")).toMatchObject({ passed: false, status_code: 200 });
  });

  it("does not make a network request from isolated product preview mode", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch");
    setPreviewTransportIsolation(true);

    await expect(api.scepQualification()).rejects.toThrow("live tenant APIs are disabled");
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
