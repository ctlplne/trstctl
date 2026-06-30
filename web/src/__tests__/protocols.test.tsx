import { beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { Protocols } from "@/pages/Protocols";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    protocolStatuses: vi.fn(),
    acmeDNS01Providers: vi.fn(),
    acmeDNS01ProviderConfigs: vi.fn(),
  },
}));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...apiMock } };
});

async function renderProtocols() {
  const result = render(
    <MemoryRouter>
      <Protocols />
    </MemoryRouter>,
  );
  await waitFor(() => expect(apiMock.protocolStatuses).toHaveBeenCalledTimes(1));
  await waitFor(() => expect(apiMock.acmeDNS01Providers).toHaveBeenCalledTimes(1));
  await waitFor(() => expect(apiMock.acmeDNS01ProviderConfigs).toHaveBeenCalledTimes(1));
  await screen.findByText("ACME directory responded.");
  return result;
}

function installClipboardSpy() {
  const writeText = vi.fn().mockResolvedValue(undefined);
  const clipboard = { writeText };
  Object.defineProperty(window.navigator, "clipboard", {
    configurable: true,
    value: clipboard,
  });
  Object.defineProperty(globalThis.navigator, "clipboard", {
    configurable: true,
    value: clipboard,
  });
  return writeText;
}

describe("protocol surface", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    apiMock.protocolStatuses.mockReset();
    apiMock.acmeDNS01Providers.mockReset();
    apiMock.acmeDNS01ProviderConfigs.mockReset();
    apiMock.protocolStatuses.mockResolvedValue({
      source: "public_responder_probe",
      checked_at: "2026-06-26T14:00:00Z",
      items: [
        {
          protocol: "acme",
          endpoint: "/directory",
          enabled: true,
          served: true,
          status_code: 200,
          detail: "ACME directory responded.",
        },
        {
          protocol: "est",
          endpoint: "/.well-known/est/cacerts",
          enabled: true,
          served: true,
          status_code: 200,
          detail: "EST CA-certs responder returned a chain.",
        },
        {
          protocol: "scep",
          endpoint: "/scep?operation=GetCACaps",
          enabled: false,
          served: false,
          status_code: 404,
          detail: "SCEP responder is not mounted.",
        },
        {
          protocol: "cmp",
          endpoint: "/cmp",
          enabled: true,
          served: true,
          status_code: 405,
          detail: "CMP route is mounted and expects a PKIMessage request.",
        },
        {
          protocol: "spiffe",
          endpoint: "unix:///tmp/trstctl-spiffe-workload.sock",
          enabled: true,
          served: true,
          status_code: 0,
          detail: "Workload API socket configured.",
        },
        {
          protocol: "ssh",
          endpoint: "/ssh/ca",
          enabled: true,
          served: true,
          status_code: 200,
          detail: "SSH CA public-key endpoint responded.",
        },
        {
          protocol: "tsa",
          endpoint: "/tsa",
          enabled: true,
          served: true,
          status_code: 405,
          detail: "TSA route is mounted and expects a timestamp request.",
        },
      ],
    });
    apiMock.acmeDNS01Providers.mockResolvedValue({
      items: [
        provider("route53", "AWS Route 53", "hosted-dns", ["hosted_zone_id", "aws_secret_key_ref"], ["net.dial:route53.amazonaws.com"]),
        provider("googledns", "Google Cloud DNS", "hosted-dns", ["project", "managed_zone", "oauth_token_ref"], ["net.dial:dns.googleapis.com"]),
        provider("azuredns", "Azure DNS", "hosted-dns", ["subscription_id", "resource_group", "zone", "aad_token_ref"], ["net.dial:management.azure.com"]),
        provider("cloudflare", "Cloudflare DNS", "hosted-dns", ["zone_id", "api_token_ref"], ["net.dial:api.cloudflare.com"]),
        provider("rfc2136", "RFC 2136 dynamic DNS", "dynamic-dns", ["server", "zone", "tsig_secret_ref"], ["net.dial:authoritative-dns-server"]),
        provider("webhook", "Generic DNS webhook", "webhook", ["endpoint", "bearer_token_ref"], ["net.dial:webhook-host"]),
      ],
    });
    apiMock.acmeDNS01ProviderConfigs.mockResolvedValue({
      items: [
        {
          id: "01900000-0000-7000-8000-000000000069",
          tenant_id: "11111111-1111-1111-1111-111111111111",
          name: "prod-cloudflare",
          provider: "cloudflare",
          zone: "example.test",
          challenge_domain: "_acme-challenge.example.test",
          delegation_target: "tenant-123.auth.acme-dns.example.net",
          credential_refs: { api_token_ref: "secret://dns/cloudflare/api-token" },
          config: { zone_id: "zone-prod" },
          caa_issuer_domain: "trstctl.example",
          allowed_methods: ["dns-01"],
          allow_wildcards: true,
          secret_handling: "credential_refs_only",
          created_at: "2026-06-26T14:00:00Z",
          updated_at: "2026-06-26T14:00:00Z",
        },
      ],
    });
  });

  it("renders ACME setup with live responder status", async () => {
    const writeText = installClipboardSpy();
    await renderProtocols();

    expect(screen.getByRole("heading", { name: "Protocols" })).toBeInTheDocument();
    expect(screen.getAllByText("ACME directory, account, order, challenge, and certificate issuance flow").length).toBeGreaterThan(0);
    expect(screen.getAllByText("Protocol enabled").length).toBeGreaterThan(0);
    expect(screen.getAllByText("Tenant binding").length).toBeGreaterThan(0);
    expect(screen.getByRole("heading", { name: "Protocol responder status" })).toBeInTheDocument();
    expect(screen.getByText("Read-only responder probe")).toBeInTheDocument();
    expect(screen.getAllByText("Enabled").length).toBeGreaterThan(0);
    expect(screen.getByText("/directory")).toBeInTheDocument();
    expect(screen.getAllByText("HTTP 200").length).toBeGreaterThan(0);
    expect(screen.getByText(/issuance refuses requests when no issuing CA\/profile/i)).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "DNS-01 providers" })).toBeInTheDocument();
    for (const name of ["AWS Route 53", "Google Cloud DNS", "Azure DNS", "Cloudflare DNS", "RFC 2136 dynamic DNS", "Generic DNS webhook"]) {
      expect(screen.getByText(name)).toBeInTheDocument();
    }
    expect(screen.getAllByText("present-validate-cleanup").length).toBeGreaterThanOrEqual(6);
    expect(screen.getAllByText("No raw secret fields").length).toBeGreaterThanOrEqual(6);
    expect(screen.getByText("tsig_secret_ref")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "DNS-01 provider configs" })).toBeInTheDocument();
    expect(screen.getByText("prod-cloudflare")).toBeInTheDocument();
    expect(screen.getAllByText("cloudflare").length).toBeGreaterThanOrEqual(2);
    expect(screen.getByText("example.test")).toBeInTheDocument();
    expect(screen.getByText("tenant-123.auth.acme-dns.example.net")).toBeInTheDocument();
    expect(screen.getByText("credential_refs_only")).toBeInTheDocument();
    expect(screen.getByText("Wildcards allowed")).toBeInTheDocument();
    expect(screen.getByText("CAA trstctl.example")).toBeInTheDocument();
    expect(screen.getAllByText("api_token_ref").length).toBeGreaterThanOrEqual(2);
    expect(screen.queryByText("secret://dns/cloudflare/api-token")).not.toBeInTheDocument();
    expect(screen.queryByText("zone-prod")).not.toBeInTheDocument();
    expect(screen.queryByText("Status unknown to console")).not.toBeInTheDocument();
    expect(screen.queryByText(/^active$/i)).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Copy ACME certbot command" }));

    await waitFor(() => expect(writeText).toHaveBeenCalledWith(expect.stringContaining("--server https://trstctl.example.test/directory")));
    expect(writeText).toHaveBeenCalledWith(expect.not.stringMatching(/Bearer|token|password/i));
    expect(screen.getByText("Copied command without token material.")).toBeInTheDocument();
  });

  it("renders EST, SCEP, and CMP with live responder routes and no transcript placeholders", async () => {
    await renderProtocols();

    expect(screen.getAllByText("CA certificate download and simple enrollment flow").length).toBeGreaterThan(0);
    expect(screen.getAllByText("SCEP CA discovery and PKI operation flow").length).toBeGreaterThan(0);
    expect(screen.getAllByText("CMP enrollment request flow").length).toBeGreaterThan(0);
    expect(screen.getAllByText("RA key file").length).toBe(2);
    expect(screen.getByText("/scep?operation=GetCACaps")).toBeInTheDocument();
    expect(screen.getByText("SCEP responder is not mounted.")).toBeInTheDocument();
    expect(screen.getAllByText("Off").length).toBeGreaterThan(0);
    expect(screen.getByText("/cmp")).toBeInTheDocument();
    expect(screen.getByText("CMP route is mounted and expects a PKIMessage request.")).toBeInTheDocument();
    expect(screen.getAllByText("Served").length).toBeGreaterThan(0);
    expect(screen.queryByText("EST enrollment transcript coming soon")).not.toBeInTheDocument();
    expect(screen.queryByText("SCEP enrollment transcript coming soon")).not.toBeInTheDocument();
    expect(screen.queryByText("CMP enrollment transcript coming soon")).not.toBeInTheDocument();
    expect(screen.queryByText(/does not invent order, challenge, or transcript data/i)).not.toBeInTheDocument();
  });

  it("renders SPIFFE, SSH CA, and TSA setup without exposing private key material", async () => {
    const writeText = installClipboardSpy();
    await renderProtocols();

    expect(screen.getAllByText("Workload API socket issuing X.509-SVID and JWT-SVID credentials").length).toBeGreaterThan(0);
    expect(screen.getByText("Trust domain")).toBeInTheDocument();
    expect(screen.getByText("unix:///tmp/trstctl-spiffe-workload.sock")).toBeInTheDocument();
    expect(screen.getByText("Workload API socket configured.")).toBeInTheDocument();
    expect(screen.getByText(/X.509-SVID and JWT-SVID support/i)).toBeInTheDocument();

    expect(screen.getAllByText("SSH CA public key, user/host certificate issuance, and revocation list flow").length).toBeGreaterThan(0);
    expect(screen.getByText("SSH CA public-key endpoint responded.")).toBeInTheDocument();
    expect(screen.getByText(/OpenSSH binary KRL/i)).toBeInTheDocument();

    expect(screen.getAllByText("RFC 3161 timestamp request flow").length).toBeGreaterThan(0);
    expect(screen.getByText("TSA certificate file")).toBeInTheDocument();
    expect(screen.getByText("/tsa")).toBeInTheDocument();
    expect(screen.getByText("TSA route is mounted and expects a timestamp request.")).toBeInTheDocument();
    expect(screen.getByText(/openssl ts -query/i)).toBeInTheDocument();
    expect(screen.getByText(/openssl ts -verify/i)).toBeInTheDocument();
    expect(screen.queryByText("SPIFFE live workload status coming soon")).not.toBeInTheDocument();
    expect(screen.queryByText("SSH issue/revoke log coming soon")).not.toBeInTheDocument();
    expect(screen.queryByText("TSA issuance health coming soon")).not.toBeInTheDocument();
    expect(screen.queryByText(/BEGIN PRIVATE KEY/)).not.toBeInTheDocument();
    expect(screen.queryByText(/BEGIN OPENSSH PRIVATE KEY/)).not.toBeInTheDocument();
    expect(screen.queryByText(/SVID private key:/i)).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Copy TSA HTTP POST command" }));

    await waitFor(() => expect(writeText).toHaveBeenCalledWith(expect.stringContaining("https://trstctl.example.test/tsa")));
    expect(writeText).toHaveBeenCalledWith(expect.not.stringMatching(/PRIVATE KEY|password/i));
  });

  it("hides ARI, DNS validation, CAA, wildcard, and MDM fixture sections", async () => {
    await renderProtocols();

    expect(screen.queryByRole("heading", { name: "ACME Renewal Information (ARI)" })).not.toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "ACME DNS validation" })).not.toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Intune / MDM enrollment" })).not.toBeInTheDocument();
    expect(screen.queryByText("ACME responder")).not.toBeInTheDocument();
    expect(screen.queryByText("secret://dns/cloudflare/prod")).not.toBeInTheDocument();
    expect(screen.queryByText("_acme-challenge.example.test CNAME _acme-challenge.acme-validation.example.net")).not.toBeInTheDocument();
    expect(screen.queryByText("No CAA record")).not.toBeInTheDocument();
    expect(screen.queryByText("CAA allowed issuer")).not.toBeInTheDocument();
    expect(screen.queryByText("CAA denied issuer")).not.toBeInTheDocument();
    expect(screen.queryByText("CAA DNS failure")).not.toBeInTheDocument();
    expect(screen.queryByText("Wildcard CAA")).not.toBeInTheDocument();
    expect(screen.queryByText("TLS-ALPN-01")).not.toBeInTheDocument();
    expect(screen.queryByText("challenge-required")).not.toBeInTheDocument();
    expect(screen.queryByText("challenge-missing")).not.toBeInTheDocument();
    expect(screen.queryByText("scep-disabled")).not.toBeInTheDocument();
    expect(screen.queryByText(/Renewal-window publishing stays read-only/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/Raw DNS provider tokens are never typed into this console/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/Wildcard issuance requires explicit operator acknowledgement/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/run outside this console today/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/Challenge rotation and enrollment failures stay in fixture form/i)).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /enable ari|publish ari|set renewal window/i })).not.toBeInTheDocument();
    expect(screen.queryByRole("textbox", { name: /token|api token|provider token/i })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /activate|preflight|save provider/i })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /issue wildcard|acknowledge wildcard|run challenge/i })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /rotate challenge|sync intune|retry enrollment/i })).not.toBeInTheDocument();
  });
});

function provider(name: string, displayName: string, kind: string, credentialReferenceFields: string[], capabilities: string[]) {
  return {
    name,
    display_name: displayName,
    kind,
    served: true,
    propagation_preflight: true,
    conformance: "present-validate-cleanup",
    credential_reference_fields: credentialReferenceFields,
    secret_fields: [],
    capabilities,
    provider_package: `internal/dns/${name}`,
    notes: "served DNS-01 provider",
  };
}
