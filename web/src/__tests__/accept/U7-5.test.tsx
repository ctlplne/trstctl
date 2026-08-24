import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { CodeSigning } from "@/pages/CodeSigning";
import { AppQueryProvider } from "@/lib/query";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
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
    await user.click(screen.getByRole("button", { name: "Keyless (Fulcio)" }));
    await user.type(screen.getByLabelText("Artifact digest"), `sha256:${"f".repeat(64)}`);
    await user.type(screen.getByLabelText("Identity payload"), "header.payload.signature");
    await user.click(screen.getByRole("button", { name: "Sign artifact" }));

    await waitFor(() =>
      expect(apiMock.signCodeKeyless).toHaveBeenCalledWith({
        artifact_type: "container",
        digest: "//////////////////////////////////////////8=",
        identity_method: "github_oidc",
        identity_payload: "aGVhZGVyLnBheWxvYWQuc2lnbmF0dXJl",
      }),
    );
    expect(await screen.findByText("Signature receipt")).toBeInTheDocument();
    expect(screen.getByText("https://oauth2.example")).toBeInTheDocument();
    expect(screen.getByText("acme/payments/.github/workflows/release.yml@refs/heads/main")).toBeInTheDocument();
    expect(screen.getByText("KEYLESSBASE64SIG")).toBeInTheDocument();
    expect(screen.getByText("transparency.rekor")).toBeInTheDocument();
  });
});
