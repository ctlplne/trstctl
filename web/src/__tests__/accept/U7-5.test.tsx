import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { CodeSigning } from "@/pages/CodeSigning";
import { AppQueryProvider } from "@/lib/query";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    previewCodeKeyless: vi.fn(),
    signCode: vi.fn(),
    signCodeKeyless: vi.fn(),
    codeSigningIdentities: vi.fn(),
    approvalRequests: vi.fn(),
    protocolStatuses: vi.fn(),
  },
}));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...apiMock } };
});

beforeEach(() => {
  apiMock.previewCodeKeyless.mockReset().mockResolvedValue({
    capability: "F50",
    operation: "sign_code_artifact_keyless",
    mode: "keyless",
    ready: true,
    effect_free: true,
    artifact_type: "container",
    digest_sha256: "f".repeat(64),
    identity_method: "github_oidc",
    required_permission: "keys:write",
    request_fingerprint: `sha256:${"a".repeat(64)}`,
    configuration_fingerprint: `sha256:${"b".repeat(64)}`,
    signing_algorithm: "ECDSA-P256",
    transparency_destination: "transparency.rekor",
    approval_required: false,
    blockers: [],
    preview_reads: ["read identity-provider metadata"],
    preview_writes: [],
    preview_external_effects: [],
    execute_writes: ["append one immutable command"],
    execute_external_effects: ["ask the isolated signer"],
    recovery_steps: ["retry the identical reviewed request"],
    verification_steps: ["verify the signature"],
    cli_argv: ["trstctl-cli", "code-signing", "keyless-preview", "-f", "code-signing.json"],
    secret_data_handling: "The proof is bound to the review but never rendered.",
  });
  apiMock.signCode.mockReset();
  apiMock.signCodeKeyless.mockReset().mockResolvedValue({
    algorithm: "ECDSA-P256",
    artifact_type: "container",
    fulcio_issuer: "https://oauth2.example",
    fulcio_san: "acme/payments/.github/workflows/release.yml@refs/heads/main",
    public_key_der: "BASE64DER",
    signature: "KEYLESSBASE64SIG",
    transparency_destination: "transparency.rekor",
  });
  apiMock.codeSigningIdentities.mockReset().mockResolvedValue({ items: [], total: 0, verified_count: 0, not_published_count: 0 });
  apiMock.approvalRequests.mockReset().mockResolvedValue([]);
  apiMock.protocolStatuses.mockReset().mockResolvedValue({
    source: "public_responder_probe",
    checked_at: "2026-08-24T12:00:00Z",
    items: [{ protocol: "tsa", endpoint: "/tsa", enabled: true, served: true, status_code: 200 }],
  });
});

describe("U7-5 code-signing console (keyless)", () => {
  it("submits a keyless signing request to the served endpoint and renders the receipt", async () => {
    const user = userEvent.setup();
    render(
      <AppQueryProvider>
        <MemoryRouter>
          <CodeSigning />
        </MemoryRouter>
      </AppQueryProvider>,
    );
    await user.click(screen.getByRole("button", { name: "Verified keyless identity" }));
    await user.type(screen.getByLabelText("Artifact digest"), `sha256:${"f".repeat(64)}`);
    await user.type(screen.getByLabelText("Short-lived identity proof"), "header.payload.signature");
    await user.click(screen.getByRole("button", { name: "Review signing plan" }));

    await waitFor(() =>
      expect(apiMock.previewCodeKeyless).toHaveBeenCalledWith({
        artifact_type: "container",
        digest: "//////////////////////////////////////////8=",
        identity_method: "github_oidc",
        identity_payload: "aGVhZGVyLnBheWxvYWQuc2lnbmF0dXJl",
      }),
    );
    await user.click(screen.getByRole("button", { name: "Sign this reviewed digest" }));

    await waitFor(() =>
      expect(apiMock.signCodeKeyless).toHaveBeenCalledWith(
        {
          artifact_type: "container",
          digest: "//////////////////////////////////////////8=",
          identity_method: "github_oidc",
          identity_payload: "aGVhZGVyLnBheWxvYWQuc2lnbmF0dXJl",
          preview_fingerprint: `sha256:${"a".repeat(64)}`,
        },
        expect.stringMatching(/^codesign-/),
      ),
    );
    expect(await screen.findByText("Signature receipt")).toBeInTheDocument();
    expect(screen.getByText("https://oauth2.example")).toBeInTheDocument();
    expect(screen.getByText("acme/payments/.github/workflows/release.yml@refs/heads/main")).toBeInTheDocument();
    expect(screen.getByText("KEYLESSBASE64SIG")).toBeInTheDocument();
    expect(screen.getAllByText("transparency.rekor").length).toBeGreaterThan(0);
  });
});
