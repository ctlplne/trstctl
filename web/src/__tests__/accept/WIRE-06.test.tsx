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

describe("WIRE-06 ephemeral API-key issuance wiring", () => {
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
    apiMock.issueEphemeralAPIKey.mockResolvedValue({
      id: "33333333-3333-3333-3333-333333333333",
      tenant_id: "44444444-4444-4444-4444-444444444444",
      subject: "ci/deploy-preview",
      scopes: ["repo:payments:read", "deploy:staging:write"],
      created_at: "2026-06-19T13:00:00Z",
      expires_at: "2026-06-19T13:15:00Z",
      token: "epk_live_reveal_once_123",
    });
  });

  it("issues a served ephemeral API key, reveals the token once, then drops it on dismissal", async () => {
    const storageSpy = vi.spyOn(Storage.prototype, "setItem");
    const user = userEvent.setup();
    renderSecrets("/secrets/sharing");

    await user.click(await screen.findByRole("button", { name: "Open temporary access" }));
    expect(await screen.findByRole("heading", { name: "Ephemeral API keys" })).toBeInTheDocument();
    const issueForm = within(screen.getByRole("form", { name: "Issue ephemeral API key" }));
    await user.type(issueForm.getByLabelText("Subject"), "ci/deploy-preview");
    await user.type(issueForm.getByLabelText("Scopes"), "repo:payments:read, deploy:staging:write");
    await user.clear(issueForm.getByLabelText("TTL seconds"));
    await user.type(issueForm.getByLabelText("TTL seconds"), "900");
    await user.click(issueForm.getByRole("button", { name: /issue api key/i }));

    await waitFor(() =>
      expect(apiMock.issueEphemeralAPIKey).toHaveBeenCalledWith({
        subject: "ci/deploy-preview",
        scopes: ["repo:payments:read", "deploy:staging:write"],
        ttl_seconds: 900,
      }),
    );
    expect(await screen.findByText("epk_live_reveal_once_123")).toBeInTheDocument();
    expect(screen.getByText("33333333-3333-3333-3333-333333333333")).toBeInTheDocument();
    expect(issueForm.getByLabelText("Subject")).toHaveValue("");

    await user.click(screen.getByRole("button", { name: /dismiss/i }));
    expect(screen.queryByText("epk_live_reveal_once_123")).not.toBeInTheDocument();
    expect(storageSpy).not.toHaveBeenCalled();
    expect(localStorage.length).toBe(0);
    expect(sessionStorage.length).toBe(0);
  });

  it("removes the ephemeral API-key fixture table", () => {
    const source = readFileSync(path.join(process.cwd(), "src/pages/Secrets.tsx"), "utf8");
    expect(source).not.toMatch(/const\s+ephemeralKeyRows/);
    expect(source).not.toMatch(/Ephemeral API key request fixtures/);
  });
});
