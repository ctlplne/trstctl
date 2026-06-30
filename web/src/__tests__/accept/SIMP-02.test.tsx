import { readFileSync } from "node:fs";
import path from "node:path";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
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

function renderProtocols() {
  return render(
    <MemoryRouter>
      <Protocols />
    </MemoryRouter>,
  );
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

describe("SIMP-02 lean protocol setup", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    apiMock.protocolStatuses.mockReset();
    apiMock.acmeDNS01Providers.mockReset();
    apiMock.acmeDNS01ProviderConfigs.mockReset();
    apiMock.protocolStatuses.mockResolvedValue({
      source: "public_responder_probe",
      checked_at: "2026-06-26T14:30:00Z",
      items: [
        { protocol: "acme", endpoint: "/directory", enabled: true, served: true, status_code: 200, detail: "ACME directory responded." },
        { protocol: "est", endpoint: "/.well-known/est/cacerts", enabled: true, served: true, status_code: 200, detail: "EST CA-certs responder returned a chain." },
        { protocol: "scep", endpoint: "/scep?operation=GetCACaps", enabled: false, served: false, status_code: 404, detail: "SCEP responder is not mounted." },
        { protocol: "cmp", endpoint: "/cmp", enabled: true, served: true, status_code: 405, detail: "CMP route is mounted and expects a PKIMessage request." },
        { protocol: "spiffe", endpoint: "unix:///tmp/trstctl-spiffe-workload.sock", enabled: true, served: true, status_code: 0, detail: "Workload API socket configured." },
        { protocol: "ssh", endpoint: "/ssh/ca", enabled: true, served: true, status_code: 200, detail: "SSH CA public-key endpoint responded." },
        { protocol: "tsa", endpoint: "/tsa", enabled: true, served: true, status_code: 405, detail: "TSA route is mounted and expects a timestamp request." },
      ],
    });
    apiMock.acmeDNS01Providers.mockResolvedValue({
      items: [
        {
          name: "route53",
          display_name: "AWS Route 53",
          kind: "hosted-dns",
          served: true,
          propagation_preflight: true,
          conformance: "present-validate-cleanup",
          credential_reference_fields: ["hosted_zone_id", "aws_secret_key_ref"],
          secret_fields: [],
          capabilities: ["net.dial:route53.amazonaws.com"],
          provider_package: "internal/dns/route53",
          notes: "served DNS-01 provider",
        },
      ],
    });
    apiMock.acmeDNS01ProviderConfigs.mockResolvedValue({ items: [] });
  });

  it("shows each protocol with live status, route, and client snippet only", async () => {
    const writeText = installClipboardSpy();
    renderProtocols();

    await waitFor(() => expect(apiMock.protocolStatuses).toHaveBeenCalledTimes(1));
    await waitFor(() => expect(apiMock.acmeDNS01Providers).toHaveBeenCalledTimes(1));
    await waitFor(() => expect(apiMock.acmeDNS01ProviderConfigs).toHaveBeenCalledTimes(1));
    for (const name of ["ACME", "EST", "SCEP", "CMP", "SPIFFE", "SSH CA", "TSA"]) {
      expect(screen.getAllByText(name).length).toBeGreaterThan(0);
    }
    for (const endpoint of ["/directory", "/.well-known/est/cacerts", "/scep?operation=GetCACaps", "/cmp", "unix:///tmp/trstctl-spiffe-workload.sock", "/ssh/ca", "/tsa"]) {
      expect(screen.getAllByText(endpoint).length).toBeGreaterThan(0);
    }

    const acmeRow = within(screen.getByRole("row", { name: /ACME ACME directory/i }));
    expect(acmeRow.getByText("Enabled")).toBeInTheDocument();
    expect(acmeRow.getByText("HTTP 200")).toBeInTheDocument();

    expect(screen.getByRole("button", { name: "Copy ACME certbot command" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Copy TSA HTTP POST command" })).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Copy TSA HTTP POST command" }));
    await waitFor(() => expect(writeText).toHaveBeenCalledWith(expect.stringContaining("https://trstctl.example.test/tsa")));

    expect(screen.queryByRole("heading", { name: "ACME Renewal Information (ARI)" })).not.toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "DNS-01 providers" })).toBeInTheDocument();
    expect(screen.getByText("AWS Route 53")).toBeInTheDocument();
    expect(screen.getByText("No raw secret fields")).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Intune / MDM enrollment" })).not.toBeInTheDocument();
    expect(document.body.textContent).not.toMatch(/fixture|preview|coming soon|not served yet|secret:\/\/dns|wasm:dns/i);
    expect(document.body.textContent).not.toMatch(/CNAME validation|CAA policy|Validation method|challenge-required|No CAA record|TLS-ALPN-01|Wildcard/i);
  });

  it("removes protocol reference-only fixtures from the module", () => {
    const source = readFileSync(path.join(process.cwd(), "src/pages/Protocols.tsx"), "utf8");
    expect(source).not.toMatch(/ariSignals|dnsProviderDisclosures|cnameFixtures|caaFixtures|validationMethodFixtures|mdmFixtures/);
    expect(source).not.toMatch(/FixtureTable|UnavailableState|DnsProviderDisclosure|ValidationFixture|AriSignal/);
    expect(source).not.toMatch(/ACME Renewal Information|ACME DNS validation|Intune \/ MDM enrollment|DNS provider and plugin disclosure/);
    expect(source).not.toMatch(/coming soon|fixture|preview/i);
  });
});
