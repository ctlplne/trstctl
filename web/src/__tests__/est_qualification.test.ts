import { afterEach, describe, expect, it, vi } from "vitest";
import { api, setPreviewTransportIsolation } from "@/lib/api";

describe("EST qualification transport", () => {
  afterEach(() => {
    setPreviewTransportIsolation(false);
    vi.restoreAllMocks();
  });

  it("proves the public CA, CSR-rules, and fail-closed auth doors without credentials or a CSR", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
      const path = String(input);
      if (path === "/.well-known/est/cacerts") {
        return new Response("MAE=", {
          status: 200,
          headers: { "Content-Type": "application/pkcs7-mime", "Content-Transfer-Encoding": "base64" },
        });
      }
      if (path === "/.well-known/est/csrattrs") return new Response(null, { status: 204 });
      if (path === "/.well-known/est/simpleenroll") {
        return new Response(null, { status: 401, headers: { "WWW-Authenticate": 'Bearer realm="est", scope="certs:request"' } });
      }
      throw new Error(`unexpected fetch ${path}`);
    });

    const result = await api.estQualification();

    expect(result.passed).toBe(true);
    expect(result.checks.map((check) => [check.id, check.status_code, check.passed])).toEqual([
      ["ca-chain", 200, true],
      ["csr-rules", 204, true],
      ["auth-gate", 401, true],
    ]);
    expect(fetchMock).toHaveBeenCalledTimes(3);
    expect(fetchMock).toHaveBeenNthCalledWith(
      1,
      "/.well-known/est/cacerts",
      expect.objectContaining({ method: "GET", credentials: "omit" }),
    );
    expect(fetchMock).toHaveBeenNthCalledWith(3, "/.well-known/est/simpleenroll", expect.objectContaining({ method: "POST", credentials: "omit" }));
    const enrollInit = fetchMock.mock.calls[2]?.[1] as RequestInit;
    expect(enrollInit.body).toBeUndefined();
    expect(enrollInit.headers).not.toMatchObject({ Authorization: expect.anything() });
  });

  it("fails closed when the enrollment door accepts a credential-free request", async () => {
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
      const path = String(input);
      if (path.endsWith("cacerts")) {
        return new Response("MAE=", {
          status: 200,
          headers: { "Content-Type": "application/pkcs7-mime", "Content-Transfer-Encoding": "base64" },
        });
      }
      if (path.endsWith("csrattrs")) return new Response(null, { status: 204 });
      return new Response(null, { status: 200 });
    });

    const result = await api.estQualification();

    expect(result.passed).toBe(false);
    expect(result.checks.find((check) => check.id === "auth-gate")).toMatchObject({ passed: false, status_code: 200 });
  });

  it("does not make a network request from isolated product preview mode", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch");
    setPreviewTransportIsolation(true);

    await expect(api.estQualification()).rejects.toThrow("live tenant APIs are disabled");
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
