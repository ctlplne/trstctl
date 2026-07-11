import { describe, expect, it, vi, beforeEach } from "vitest";
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
  apiMock.signCode.mockReset().mockResolvedValue({
    algorithm: "ECDSA-P256",
    artifact_type: "container",
    key_id: "key-1",
    public_key_der: "BASE64DER",
    signature: "BASE64SIG",
    transparency_destination: "transparency.rekor",
  });
  apiMock.signCodeKeyless
    .mockReset()
    .mockResolvedValue({ algorithm: "ECDSA-P256", artifact_type: "container", fulcio_issuer: "https://oauth2.example", public_key_der: "BASE64DER", signature: "BASE64SIG" });
});

describe("code signing console", () => {
  it("submits a key-backed signing request and renders the served signature receipt", async () => {
    const user = userEvent.setup();
    render(
      <MemoryRouter>
        <CodeSigning />
      </MemoryRouter>,
    );
    expect(screen.getByRole("heading", { name: "Code signing" })).toBeInTheDocument();
    await user.type(screen.getByLabelText("Artifact digest"), "sha256:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    await user.type(screen.getByLabelText("Managed key id"), "key-1");
    await user.click(screen.getByRole("button", { name: "Sign artifact" }));

    await waitFor(() =>
      expect(apiMock.signCode).toHaveBeenCalledWith({
        artifact_type: "container",
        digest: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
        key_id: "key-1",
      }),
    );
    expect(await screen.findByText("Signature receipt")).toBeInTheDocument();
    expect(screen.getByText("ECDSA-P256")).toBeInTheDocument();
    expect(screen.getByText("BASE64SIG")).toBeInTheDocument();
    expect(screen.getByText("transparency.rekor")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Download signature" })).toHaveAttribute("download", "artifact.sig");
    // The signer boundary holds: no private key material ever reaches the browser.
    expect(screen.queryByText(/BEGIN .* PRIVATE KEY/)).not.toBeInTheDocument();
  });
});
