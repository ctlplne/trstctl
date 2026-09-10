import { webcrypto } from "node:crypto";
import { afterEach, vi, type Mock } from "vitest";
import { bindFirstCertificatePrincipal } from "@/lib/firstCertificateMemory";

// Test-only fixed HTTP doubles. These envelopes are not valid crypto fixtures,
// and this helper does not prove server idempotency, signer custody or TLS.
export const wizardFixtureCSR = "-----BEGIN CERTIFICATE REQUEST-----\nAQID\n-----END CERTIFICATE REQUEST-----";
export const wizardFixturePrincipal = { tenantId: "t1", subject: "operator-1" };
export function installWizardWireFixture(mock: Record<string, Mock>, identityID = "id-1") {
  bindFirstCertificatePrincipal(null);
  bindFirstCertificatePrincipal(wizardFixturePrincipal);
  vi.stubGlobal("crypto", webcrypto);
  let identity: Record<string, unknown> = {};
  let transitioned = false;
  vi.stubGlobal(
    "fetch",
    vi.fn(async (path: RequestInfo | URL, init?: RequestInit) => {
      const url = String(path);
      let value: unknown;
      if (url === "/auth/me") value = { tenant_id: "t1", subject: "operator-1" };
      else if (url === "/api/v1/owners") value = { tenant_id: "t1", ...(await mock.createOwner(JSON.parse(init!.body as string))) };
      else if (url.startsWith("/api/v1/owners/") && url.endsWith("/attest")) value = { tenant_id: "t1", ...(await mock.attestOwner(url.split("/")[4])) };
      else if (url === "/api/v1/identities") {
        identity = { ...JSON.parse(init!.body as string), id: identityID, tenant_id: "t1", status: "requested" };
        value = identity;
      } else if (url.endsWith("/transitions")) {
        await mock.transitionIdentity(JSON.parse(init!.body as string));
        identity = { ...identity, status: "issued" };
        transitioned = true;
        value = identity;
      } else if (url.includes("/issuance-result?")) {
        if (!transitioned) return new Response("{}", { status: 404 });
        value = {
          identity_id: identity.id,
          request_key: new URL(url, "https://fixture.invalid").searchParams.get("request_key"),
          state: "issued",
          certificate: {
            id: "cert-1",
            tenant_id: "t1",
            fingerprint: "public-fixture-fingerprint",
            subject: "CN=payments",
            issuer: "Observed fixture issuer",
            key_origin: "requester",
            status: "active",
          },
          certificate_pem: "-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n",
        };
      } else if (url === `/api/v1/identities/${identityID}`) value = identity;
      else throw new Error(`unexpected fixed wizard fixture request ${url}`);
      return new Response(JSON.stringify(value), { status: 200 });
    }),
  );
}
afterEach(() => {
  bindFirstCertificatePrincipal(null);
  vi.unstubAllGlobals();
});
