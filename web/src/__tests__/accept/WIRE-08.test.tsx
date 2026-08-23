import { readFileSync } from "node:fs";
import path from "node:path";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { Secrets } from "@/pages/Secrets";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    secretPage: vi.fn(),
    createSecret: vi.fn(),
    getSecret: vi.fn(),
    rotateSecret: vi.fn(),
    deleteSecret: vi.fn(),
    issuePKISecret: vi.fn(),
    machineLogin: vi.fn(),
    createShare: vi.fn(),
    redeemShare: vi.fn(),
    issueEphemeralAPIKey: vi.fn(),
    issueDynamicLease: vi.fn(),
    renewDynamicLease: vi.fn(),
    revokeDynamicLease: vi.fn(),
    encryptTransit: vi.fn(),
    decryptTransit: vi.fn(),
    hmacTransit: vi.fn(),
    rewrapTransit: vi.fn(),
    signTransit: vi.fn(),
  },
}));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: apiMock };
});

/** S-C2: the workspace under test is a route now, not an in-page tab. */
function renderSecrets(path: string) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <Routes>
        <Route path="/secrets" element={<Secrets />} />
        <Route path="/secrets/:workspace" element={<Secrets />} />
      </Routes>
    </MemoryRouter>,
  );
}

describe("WIRE-08 transit operation wiring", () => {
  beforeEach(() => {
    localStorage.clear();
    sessionStorage.clear();
    vi.restoreAllMocks();
    for (const mock of Object.values(apiMock)) mock.mockReset();
    apiMock.secretPage.mockResolvedValue({
      items: [
        {
          name: "app/db/password",
          version: 3,
          created_at: "2026-06-18T10:00:00Z",
          updated_at: "2026-06-19T10:00:00Z",
        },
      ],
    });
    apiMock.encryptTransit.mockResolvedValue({ ciphertext: "trst:v1:ciphertext", version: 4 });
    apiMock.decryptTransit.mockResolvedValue({ plaintext: "aGVsbG8gdHJhbnNpdA==" });
  });

  it("encrypts local plaintext, clears the input, then decrypts the served ciphertext", async () => {
    const storageSpy = vi.spyOn(Storage.prototype, "setItem");
    const user = userEvent.setup();
    renderSecrets("/secrets/engines");

    await user.click(await screen.findByRole("button", { name: "Open encryption and signing" }));
    expect(await screen.findByRole("heading", { name: "Transit and KMIP" })).toBeInTheDocument();
    const transitForm = within(screen.getByRole("form", { name: "Transit encrypt and decrypt" }));
    await user.type(transitForm.getByLabelText("Key name"), "payments-pii");
    await user.type(transitForm.getByLabelText("Plaintext"), "hello transit");
    await user.type(transitForm.getByLabelText("AAD"), "tenant-a");
    await user.click(transitForm.getByRole("button", { name: /encrypt/i }));

    await waitFor(() =>
      expect(apiMock.encryptTransit).toHaveBeenCalledWith({
        key: "payments-pii",
        plaintext: "aGVsbG8gdHJhbnNpdA==",
        aad: "dGVuYW50LWE=",
      }),
    );
    expect(transitForm.getByLabelText("Plaintext")).toHaveValue("");
    expect((await screen.findAllByText("trst:v1:ciphertext")).length).toBeGreaterThan(0);
    expect(screen.getByText("v4")).toBeInTheDocument();

    await user.click(transitForm.getByRole("button", { name: /decrypt/i }));
    await waitFor(() =>
      expect(apiMock.decryptTransit).toHaveBeenCalledWith({
        key: "payments-pii",
        ciphertext: "trst:v1:ciphertext",
        aad: "dGVuYW50LWE=",
      }),
    );
    expect(await screen.findByText("hello transit")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /dismiss/i }));
    expect(screen.queryByText("hello transit")).not.toBeInTheDocument();
    expect(storageSpy).not.toHaveBeenCalled();
    expect(localStorage.length).toBe(0);
    expect(sessionStorage.length).toBe(0);
  });

  it("removes the transit/KMIP fixture table", () => {
    const source = readFileSync(path.join(process.cwd(), "src/pages/Secrets.tsx"), "utf8");
    expect(source).not.toMatch(/const\s+transitRows/);
    expect(source).not.toMatch(/Transit and KMIP fixtures/);
  });
});
