import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { CodeSigning } from "@/pages/CodeSigning";

const { apiMock } = vi.hoisted(() => ({ apiMock: { signCode: vi.fn(), signCodeKeyless: vi.fn() } }));

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
});

describe("U7-5 code-signing console (keyless)", () => {
  it("submits a keyless signing request to the served endpoint and renders the receipt", async () => {
    const user = userEvent.setup();
    render(
      <MemoryRouter>
        <CodeSigning />
      </MemoryRouter>,
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
