import { describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { Protocols } from "@/pages/Protocols";

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

describe("served-gated protocol surface", () => {
  it("renders ACME setup without claiming live enabled state", async () => {
    const writeText = installClipboardSpy();
    renderProtocols();

    expect(screen.getByRole("heading", { name: "Protocols" })).toBeInTheDocument();
    expect(screen.getAllByText("GET /directory + POST /acme/...").length).toBeGreaterThan(0);
    expect(screen.getByText("TRSTCTL_PROTOCOLS_ACME_ENABLED")).toBeInTheDocument();
    expect(screen.getByText("TRSTCTL_PROTOCOLS_ACME_TENANT_ID")).toBeInTheDocument();
    expect(screen.getAllByText(/BACKEND-PROTOCOL-STATUS/).length).toBeGreaterThan(0);
    expect(screen.getByText(/protocol servers themselves are served-gated and default off/i)).toBeInTheDocument();
    expect(screen.getByText(/issuance refuses requests when no issuing CA\/profile/i)).toBeInTheDocument();
    expect(screen.getAllByText("Status unknown to console").length).toBeGreaterThanOrEqual(4);
    expect(screen.queryByText(/^enabled$/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/^active$/i)).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Copy ACME certbot command" }));

    await waitFor(() =>
      expect(writeText).toHaveBeenCalledWith(
        expect.stringContaining("--server https://trstctl.example.test/directory"),
      ),
    );
    expect(writeText).toHaveBeenCalledWith(expect.not.stringMatching(/Bearer|token|password/i));
    expect(screen.getByText("Copied command without token material.")).toBeInTheDocument();
  });

  it("renders EST, SCEP, and CMP endpoints with transcript reads honestly unavailable", () => {
    renderProtocols();

    expect(screen.getAllByText("GET /.well-known/est/cacerts + POST /.well-known/est/simpleenroll").length).toBeGreaterThan(0);
    expect(screen.getAllByText("GET/POST /scep").length).toBeGreaterThan(0);
    expect(screen.getAllByText("POST /cmp").length).toBeGreaterThan(0);
    expect(screen.getByText("TRSTCTL_PROTOCOLS_EST_TENANT_ID")).toBeInTheDocument();
    expect(screen.getByText("TRSTCTL_PROTOCOLS_SCEP_TENANT_ID")).toBeInTheDocument();
    expect(screen.getByText("TRSTCTL_PROTOCOLS_CMP_TENANT_ID")).toBeInTheDocument();
    expect(screen.getAllByText("TRSTCTL_PROTOCOLS_RA_KEY_FILE").length).toBe(2);
    expect(screen.getByText("EST enrollment transcript not served yet")).toBeInTheDocument();
    expect(screen.getByText("SCEP enrollment transcript not served yet")).toBeInTheDocument();
    expect(screen.getByText("CMP enrollment transcript not served yet")).toBeInTheDocument();
    expect(screen.getAllByText(/does not invent order, challenge, or transcript data/i).length).toBeGreaterThan(0);
  });

  it("renders SPIFFE, SSH CA, and TSA setup without exposing private key material", async () => {
    const writeText = installClipboardSpy();
    renderProtocols();

    expect(screen.getAllByText("gRPC UDS /tmp/trstctl-spiffe-workload.sock").length).toBeGreaterThan(0);
    expect(screen.getByText("TRSTCTL_PROTOCOLS_SPIFFE_TRUST_DOMAIN")).toBeInTheDocument();
    expect(screen.getByText("SPIFFE live workload status not served yet")).toBeInTheDocument();
    expect(screen.getByText(/X.509-SVID and JWT-SVID support/i)).toBeInTheDocument();

    expect(screen.getAllByText("GET /ssh/ca + POST /ssh/issue/user|host + GET /ssh/krl").length).toBeGreaterThan(0);
    expect(screen.getByText("TRSTCTL_PROTOCOLS_SSH_TENANT_ID")).toBeInTheDocument();
    expect(screen.getByText("SSH issue/revoke log not served yet")).toBeInTheDocument();
    expect(screen.getByText(/OpenSSH binary KRL/i)).toBeInTheDocument();

    expect(screen.getAllByText("POST /tsa").length).toBeGreaterThan(0);
    expect(screen.getByText("TRSTCTL_PROTOCOLS_TSA_CERT_FILE")).toBeInTheDocument();
    expect(screen.getByText("TSA issuance health not served yet")).toBeInTheDocument();
    expect(screen.getByText(/openssl ts -query/i)).toBeInTheDocument();
    expect(screen.getByText(/openssl ts -verify/i)).toBeInTheDocument();
    expect(screen.queryByText(/BEGIN PRIVATE KEY/)).not.toBeInTheDocument();
    expect(screen.queryByText(/BEGIN OPENSSH PRIVATE KEY/)).not.toBeInTheDocument();
    expect(screen.queryByText(/SVID private key:/i)).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Copy TSA HTTP POST command" }));

    await waitFor(() =>
      expect(writeText).toHaveBeenCalledWith(expect.stringContaining("https://trstctl.example.test/tsa")),
    );
    expect(writeText).toHaveBeenCalledWith(expect.not.stringMatching(/PRIVATE KEY|password/i));
  });

  it("renders ARI as protocol-status gated with the durable-state caveat", () => {
    renderProtocols();

    expect(screen.getByRole("heading", { name: "ACME Renewal Information (ARI)" })).toBeInTheDocument();
    expect(screen.getByText("ACME enabled state unknown to console")).toBeInTheDocument();
    expect(screen.getByText(/Disabled in console until BACKEND-PROTOCOL-STATUS reports ACME enabled/i)).toBeInTheDocument();
    expect(screen.getByText(/ARI recommendations must survive process restart/i)).toBeInTheDocument();
    expect(screen.getByText(/client renewal windows and Retry-After guidance/i)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /enable ari|publish ari|set renewal window/i })).not.toBeInTheDocument();
  });

  it("renders DNS-01 provider and plugin disclosures without raw provider-token controls", () => {
    renderProtocols();

    expect(screen.getByRole("heading", { name: "ACME DNS validation" })).toBeInTheDocument();
    expect(screen.getByText("secret://dns/cloudflare/prod")).toBeInTheDocument();
    expect(screen.getByText(/Raw DNS provider tokens are never typed into this console/i)).toBeInTheDocument();
    expect(screen.getByText("Built-in provider")).toBeInTheDocument();
    expect(screen.getByText("Plugin provider")).toBeInTheDocument();
    expect(screen.getByText(/activation is blocked until verified conformance, provenance, and capability grants are served/i)).toBeInTheDocument();
    expect(screen.queryByRole("textbox", { name: /token|api token|provider token/i })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /activate|preflight|save provider/i })).not.toBeInTheDocument();
  });

  it("renders CNAME, CAA, validation-method, and wildcard previews as non-interactive fixtures", () => {
    renderProtocols();

    expect(screen.getByText("_acme-challenge.example.test CNAME _acme-challenge.acme-validation.example.net")).toBeInTheDocument();
    expect(screen.getByText(/fails validation isolation policy/i)).toBeInTheDocument();
    expect(screen.getByText("No CAA record")).toBeInTheDocument();
    expect(screen.getByText("CAA allowed issuer")).toBeInTheDocument();
    expect(screen.getByText("CAA denied issuer")).toBeInTheDocument();
    expect(screen.getByText("CAA DNS failure")).toBeInTheDocument();
    expect(screen.getByText("Wildcard CAA")).toBeInTheDocument();
    expect(screen.getByText("HTTP-01")).toBeInTheDocument();
    expect(screen.getByText("DNS-01")).toBeInTheDocument();
    expect(screen.getByText("TLS-ALPN-01")).toBeInTheDocument();
    expect(screen.getByText("Policy denied")).toBeInTheDocument();
    expect(screen.getByText(/Wildcard issuance requires explicit operator acknowledgement/i)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /issue wildcard|acknowledge wildcard|run challenge/i })).not.toBeInTheDocument();
  });

  it("renders Intune and MDM enrollment as a SCEP-conditional library-only disclosure", () => {
    renderProtocols();

    expect(screen.getByRole("heading", { name: "Intune / MDM enrollment" })).toBeInTheDocument();
    expect(screen.getByText(/conditional on SCEP being served and enabled/i)).toBeInTheDocument();
    expect(screen.getAllByText(/BACKEND-MDM/).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/BACKEND-PROTOCOL-STATUS/).length).toBeGreaterThan(0);
    expect(screen.getByText("challenge-required")).toBeInTheDocument();
    expect(screen.getByText("challenge-missing")).toBeInTheDocument();
    expect(screen.getByText("scep-disabled")).toBeInTheDocument();
    expect(screen.getAllByText(/Intune profile guidance/i).length).toBeGreaterThan(0);
    expect(screen.getByText(/challenge rotation remains library-only/i)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /rotate challenge|sync intune|retry enrollment/i })).not.toBeInTheDocument();
  });
});
