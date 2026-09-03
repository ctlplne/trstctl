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
    previewEphemeralAPIKey: vi.fn(),
    issueEphemeralAPIKey: vi.fn(),
    verifyEphemeralAPIKey: vi.fn(),
    revokeAPIToken: vi.fn(),
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
    apiMock.previewEphemeralAPIKey.mockResolvedValue({
      capability: "F38",
      operation: "issue_ephemeral_api_key",
      ready: true,
      effect_free: true,
      subject: "ci/deploy-preview",
      scopes: ["access:read"],
      requested_ttl_seconds: 900,
      effective_ttl_seconds: 900,
      minimum_ttl_seconds: 1,
      maximum_ttl_seconds: 3600,
      required_permission: "access:write",
      request_fingerprint: "sha256:reviewed-f38",
      blockers: [],
      preview_writes: [],
      preview_external_effects: [],
      execute_writes: ["append an api_token.created event", "project one tenant-scoped token ledger row"],
      execute_external_effects: [],
      recovery_steps: ["Retry the same reviewed command with the same Idempotency-Key."],
      verification_steps: ["Use the bearer on an API allowed by its scopes.", "Revoke the key and confirm it is rejected."],
      cli_argv: ["trstctl", "ephemeral", "api-keys", "issue", "-f", "ephemeral-api-key.json"],
      token_data_handling: "The raw bearer is returned once and is never written to events or metadata reads.",
      native_secret_store_needed: false,
    });
    apiMock.issueEphemeralAPIKey.mockResolvedValue({
      id: "33333333-3333-3333-3333-333333333333",
      tenant_id: "44444444-4444-4444-4444-444444444444",
      subject: "ci/deploy-preview",
      scopes: ["access:read"],
      created_at: "2026-06-19T13:00:00Z",
      expires_at: "2026-06-19T13:15:00Z",
      token: "epk_live_reveal_once_123",
    });
  });

  it("reviews, issues, verifies, and revokes a reveal-once API key without browser persistence", async () => {
    const storageSpy = vi.spyOn(Storage.prototype, "setItem");
    const user = userEvent.setup();
    renderSecrets("/secrets/sharing");

    await user.click(await screen.findByRole("button", { name: "Open temporary access" }));
    expect(await screen.findByRole("heading", { name: "Ephemeral API keys" })).toBeInTheDocument();
    const issueForm = within(screen.getByRole("form", { name: "Review ephemeral API key" }));
    await user.type(issueForm.getByLabelText("Machine subject"), "ci/deploy-preview");
    await user.clear(issueForm.getByLabelText("Lifetime in seconds"));
    await user.type(issueForm.getByLabelText("Lifetime in seconds"), "900");
    await user.click(issueForm.getByRole("button", { name: "Review temporary key" }));

    await waitFor(() =>
      expect(apiMock.previewEphemeralAPIKey).toHaveBeenCalledWith({
        subject: "ci/deploy-preview",
        scopes: ["access:read"],
        ttl_seconds: 900,
      }),
    );
    expect(apiMock.issueEphemeralAPIKey).not.toHaveBeenCalled();
    expect(await screen.findByText("Nothing has been created yet. This plan is bound to this tenant, caller, subject, permission set, and lifetime.")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Issue reviewed key" }));

    await waitFor(() =>
      expect(apiMock.issueEphemeralAPIKey).toHaveBeenCalledWith(
        {
          subject: "ci/deploy-preview",
          scopes: ["access:read"],
          ttl_seconds: 900,
          preview_fingerprint: "sha256:reviewed-f38",
        },
        expect.any(String),
      ),
    );
    expect(await screen.findByText("epk_live_reveal_once_123")).toBeInTheDocument();
    expect(screen.getByText(/33333333-3333-3333-3333-333333333333/)).toBeInTheDocument();
    expect(issueForm.getByLabelText("Machine subject")).toHaveValue("");

    await user.click(screen.getByRole("button", { name: "Verify key access" }));
    await waitFor(() => expect(apiMock.verifyEphemeralAPIKey).toHaveBeenCalledWith("epk_live_reveal_once_123"));
    expect(await screen.findByText(/Verified: the new bearer authenticated access:read/)).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Revoke now" }));
    await waitFor(() => expect(apiMock.revokeAPIToken).toHaveBeenCalledWith("33333333-3333-3333-3333-333333333333"));
    expect(await screen.findByText(/Revoked\. The raw key was removed/)).toBeInTheDocument();

    expect(screen.queryByText("epk_live_reveal_once_123")).not.toBeInTheDocument();
    expect(storageSpy).not.toHaveBeenCalled();
    expect(localStorage.length).toBe(0);
    expect(sessionStorage.length).toBe(0);
  });

  it("reuses one recovery key after an ambiguous response and invalidates a changed review", async () => {
    apiMock.issueEphemeralAPIKey.mockRejectedValueOnce(new TypeError("connection closed after send"));
    const user = userEvent.setup();
    renderSecrets("/secrets/sharing");
    await user.click(await screen.findByRole("button", { name: "Open temporary access" }));
    const form = within(await screen.findByRole("form", { name: "Review ephemeral API key" }));
    await user.type(form.getByLabelText("Machine subject"), "ci/deploy-preview");
    await user.click(form.getByRole("button", { name: "Review temporary key" }));
    await user.click(await screen.findByRole("button", { name: "Issue reviewed key" }));

    const retry = await screen.findByRole("button", { name: "Retry same reviewed key" });
    const firstRecoveryKey = apiMock.issueEphemeralAPIKey.mock.calls[0]?.[1];
    expect(firstRecoveryKey).toEqual(expect.any(String));
    await user.click(retry);
    await waitFor(() => expect(apiMock.issueEphemeralAPIKey).toHaveBeenCalledTimes(2));
    expect(apiMock.issueEphemeralAPIKey.mock.calls[1]?.[1]).toBe(firstRecoveryKey);

    await user.click(screen.getByRole("button", { name: /dismiss/i }));
    await user.type(form.getByLabelText("Machine subject"), "ci/deploy-preview");
    await user.click(form.getByRole("button", { name: "Review temporary key" }));
    expect(await screen.findByRole("button", { name: "Issue reviewed key" })).toBeInTheDocument();
    await user.clear(form.getByLabelText("Lifetime in seconds"));
    await user.type(form.getByLabelText("Lifetime in seconds"), "60");
    expect(screen.queryByRole("button", { name: "Issue reviewed key" })).not.toBeInTheDocument();
    expect(screen.getByText("Configuration changed after review. Review the current values again.")).toBeInTheDocument();
  });

  it("removes the ephemeral API-key fixture table", () => {
    const source = readFileSync(path.join(process.cwd(), "src/pages/Secrets.tsx"), "utf8");
    expect(source).not.toMatch(/const\s+ephemeralKeyRows/);
    expect(source).not.toMatch(/Ephemeral API key request fixtures/);
  });
});
