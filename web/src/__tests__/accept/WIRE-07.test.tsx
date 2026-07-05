import { readFileSync } from "node:fs";
import path from "node:path";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
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
  },
}));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: apiMock };
});

function renderSecrets() {
  return render(
    <MemoryRouter>
      <Secrets />
    </MemoryRouter>,
  );
}

describe("WIRE-07 dynamic secret lease wiring", () => {
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
    apiMock.issueDynamicLease.mockResolvedValue({
      id: "lease-postgres-1",
      provider: "postgresql",
      role: "readonly-reporting",
      state: "active",
      issued_at: "2026-06-19T13:00:00Z",
      expires_at: "2026-06-19T13:20:00Z",
      credential: "postgres://lease-secret",
    });
    apiMock.renewDynamicLease.mockResolvedValue({
      id: "lease-postgres-1",
      provider: "postgresql",
      role: "readonly-reporting",
      state: "active",
      issued_at: "2026-06-19T13:00:00Z",
      expires_at: "2026-06-19T13:25:00Z",
    });
    apiMock.revokeDynamicLease.mockResolvedValue({
      id: "lease-postgres-1",
      provider: "postgresql",
      role: "readonly-reporting",
      state: "revoked",
      issued_at: "2026-06-19T13:00:00Z",
      expires_at: "2026-06-19T13:25:00Z",
    });
  });

  it("issues, renews, and revokes a served dynamic lease while revealing the credential once", async () => {
    const storageSpy = vi.spyOn(Storage.prototype, "setItem");
    const user = userEvent.setup();
    renderSecrets();

    await screen.findByText("app/db/password");
    await user.click(screen.getByRole("tab", { name: "Engines" }));
    const issueForm = within(screen.getByRole("form", { name: "Issue dynamic secret lease" }));
    await user.selectOptions(issueForm.getByLabelText("Provider"), "postgresql");
    await user.type(issueForm.getByLabelText("Role"), "readonly-reporting");
    await user.clear(issueForm.getByLabelText("TTL seconds"));
    await user.type(issueForm.getByLabelText("TTL seconds"), "1200");
    await user.click(issueForm.getByRole("button", { name: /issue lease/i }));

    await waitFor(() =>
      expect(apiMock.issueDynamicLease).toHaveBeenCalledWith({
        provider: "postgresql",
        role: "readonly-reporting",
        ttl_seconds: 1200,
      }),
    );
    expect(await screen.findByText("lease-postgres-1")).toBeInTheDocument();
    expect(screen.getByText("postgres://lease-secret")).toBeInTheDocument();
    expect(screen.getByText("active")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: /dismiss/i }));
    expect(screen.queryByText("postgres://lease-secret")).not.toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: /renew lease/i }));
    await waitFor(() => expect(apiMock.renewDynamicLease).toHaveBeenCalledWith("lease-postgres-1", { extend_seconds: 300 }));

    await user.click(screen.getByRole("button", { name: /revoke lease/i }));
    await waitFor(() => expect(apiMock.revokeDynamicLease).toHaveBeenCalledWith("lease-postgres-1"));
    expect(await screen.findByText("revoked")).toBeInTheDocument();
    expect(storageSpy).not.toHaveBeenCalled();
    expect(localStorage.length).toBe(0);
    expect(sessionStorage.length).toBe(0);
  });

  it("removes the dynamic-secret lease fixture table", () => {
    const source = readFileSync(path.join(process.cwd(), "src/pages/Secrets.tsx"), "utf8");
    expect(source).not.toMatch(/const\s+dynamicSecretRows/);
    expect(source).not.toMatch(/Dynamic secret backend fixtures/);
  });
});
