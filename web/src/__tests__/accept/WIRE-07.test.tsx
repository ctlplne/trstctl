import { readFileSync } from "node:fs";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { axe } from "vitest-axe";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { AppQueryProvider } from "@/lib/query";
import { Secrets } from "@/pages/Secrets";
import type { DynamicLease } from "@/lib/api";

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
    dynamicSecretProviders: vi.fn(),
    previewDynamicLease: vi.fn(),
    getDynamicLease: vi.fn(),
    issueDynamicLease: vi.fn(),
    renewDynamicLease: vi.fn(),
    revokeDynamicLease: vi.fn(),
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
      <AppQueryProvider>
        <Routes>
          <Route path="/secrets" element={<Secrets />} />
          <Route path="/secrets/:workspace" element={<Secrets />} />
        </Routes>
      </AppQueryProvider>
    </MemoryRouter>,
  );
}

const supportedProviders = ["postgresql", "mysql", "mongodb", "aws-iam", "gcp-iam", "azure-entra", "kubernetes", "redis"].map((type) => ({
  type,
  label: type,
  purpose: `Issue short-lived ${type} access.`,
  requirements: [
    {
      key: "credential_ref",
      label: "Credential reference",
      kind: "credential_reference",
      required: true,
      description: "A server-side reference; never a credential value in the browser.",
    },
  ],
}));

describe("WIRE-07 dynamic secret lease wiring", () => {
  let currentLease: DynamicLease;
  afterEach(() => vi.useRealTimers());
  beforeEach(() => {
    // Freeze Date only: fixture leases must remain live without changing real
    // browser timers, polling behavior, or production expiry enforcement.
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(new Date("2026-06-19T13:00:00Z"));
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
    apiMock.dynamicSecretProviders.mockResolvedValue({
      capability: "F65",
      configuration_mode: "startup_static",
      configuration_changes_require_restart: true,
      secret_delivery: "file_or_secret_reference",
      supported_providers: supportedProviders,
      configured_providers: [
        {
          id: "payments-db",
          type: "postgresql",
          label: "PostgreSQL",
          allowed_roles: ["readonly-reporting"],
          maximum_ttl_seconds: 3600,
          ready: true,
          configuration_revision: "runtime-revision-a",
        },
      ],
      blockers: [],
      documentation_path: "/docs/features/secrets#dynamic-secrets",
      secret_data_handling: "The browser receives readiness metadata, never provider credentials or credential-reference values.",
    });
    apiMock.previewDynamicLease.mockResolvedValue({
      capability: "F65",
      operation: "issue_dynamic_secret_lease",
      ready: true,
      effect_free: true,
      provider_id: "payments-db",
      provider_type: "postgresql",
      provider_label: "PostgreSQL",
      role: "readonly-reporting",
      requested_ttl_seconds: 1200,
      effective_ttl_seconds: 1200,
      maximum_ttl_seconds: 3600,
      configuration_revision: "runtime-revision-a",
      required_permission: "secrets:write",
      request_fingerprint: "sha256:reviewed-f65",
      blockers: [],
      preview_writes: [],
      preview_external_effects: [],
      execute_writes: ["append a tenant-scoped dynamic-secret lease event"],
      execute_external_effects: ["ask payments-db to create one readonly-reporting credential"],
      recovery_steps: ["Retry with the same Idempotency-Key after an ambiguous response."],
      verification_steps: ["Use the credential, revoke it, and prove the old login fails."],
      cli_argv: ["trstctl", "secrets", "leases", "issue", "-f", "dynamic-secret-lease.json"],
      secret_data_handling: "Execution returns the credential once; metadata reads cannot replay it.",
    });
    currentLease = {
      id: "lease-postgres-1",
      provider: "payments-db",
      role: "readonly-reporting",
      state: "active",
      issued_at: "2026-06-19T13:00:00Z",
      expires_at: "2026-06-19T13:20:00Z",
      hard_expires_at: "2026-06-19T14:00:00Z",
      revocation_status: "none",
    };
    apiMock.getDynamicLease.mockImplementation(async () => ({ ...currentLease }));
    apiMock.issueDynamicLease.mockImplementation(async () => ({ ...currentLease, credential: "postgres://lease-secret" }));
    apiMock.renewDynamicLease.mockImplementation(async () => {
      currentLease = { ...currentLease, expires_at: "2026-06-19T13:25:00Z" };
      return { ...currentLease };
    });
    apiMock.revokeDynamicLease.mockImplementation(async () => {
      currentLease = { ...currentLease, state: "revoked", revocation_status: "pending", revoked_at: "2026-06-19T13:00:00Z" };
      return { ...currentLease };
    });
  });

  it("issues, renews, and revokes a served dynamic lease while revealing the credential once", async () => {
    const storageSpy = vi.spyOn(Storage.prototype, "setItem");
    const user = userEvent.setup();
    const { container } = renderSecrets("/secrets/engines");

    await user.click(await screen.findByRole("button", { name: "Open temporary credential" }));
    expect(await screen.findByRole("heading", { name: "Temporary backend credentials" })).toBeInTheDocument();
    expect(screen.getByText("View required setup for all 8 built-in backends")).toBeInTheDocument();
    await user.selectOptions(screen.getByLabelText("Connected provider"), "payments-db");
    await user.clear(screen.getByLabelText("Lifetime in seconds"));
    await user.type(screen.getByLabelText("Lifetime in seconds"), "1200");
    await user.click(screen.getByRole("button", { name: "Review without creating" }));

    await waitFor(() =>
      expect(apiMock.previewDynamicLease).toHaveBeenCalledWith({
        provider: "payments-db",
        role: "readonly-reporting",
        ttl_seconds: 1200,
      }),
    );
    expect(apiMock.issueDynamicLease).not.toHaveBeenCalled();
    expect(await screen.findByText(/this check made no writes, opened no credential reference, and called no backend/i)).toBeInTheDocument();
    expect(await axe(container)).toHaveNoViolations();
    await user.click(screen.getByRole("button", { name: "Create reviewed credential" }));
    await waitFor(() =>
      expect(apiMock.issueDynamicLease).toHaveBeenCalledWith(
        {
          provider: "payments-db",
          role: "readonly-reporting",
          ttl_seconds: 1200,
          preview_fingerprint: "sha256:reviewed-f65",
        },
        expect.any(String),
      ),
    );
    expect(await screen.findByText("lease-postgres-1")).toBeInTheDocument();
    expect(screen.getByText("postgres://lease-secret")).toBeInTheDocument();
    expect(screen.getAllByText("active").length).toBeGreaterThanOrEqual(1);

    await user.click(screen.getByRole("button", { name: /dismiss/i }));
    expect(screen.queryByText("postgres://lease-secret")).not.toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: /renew lease/i }));
    await waitFor(() => expect(apiMock.renewDynamicLease).toHaveBeenCalledWith("lease-postgres-1", { extend_seconds: 300 }));

    await user.click(screen.getByRole("button", { name: /revoke lease/i }));
    await waitFor(() => expect(apiMock.revokeDynamicLease).toHaveBeenCalledWith("lease-postgres-1"));
    expect(await screen.findByRole("heading", { name: "Revocation queued; provider removal pending" })).toBeInTheDocument();
    expect(screen.queryByText("postgres://lease-secret")).not.toBeInTheDocument();
    currentLease = { ...currentLease, revocation_status: "completed", revocation_completed_at: "2026-06-19T13:00:05Z" };
    await user.click(screen.getByRole("button", { name: "Refresh lease status" }));
    expect(await screen.findByRole("heading", { name: "Provider confirmed credential removal" })).toBeInTheDocument();
    expect(apiMock.getDynamicLease).toHaveBeenCalledWith("lease-postgres-1", expect.any(AbortSignal));
    expect(storageSpy).not.toHaveBeenCalled();
    expect(localStorage.length).toBe(0);
    expect(sessionStorage.length).toBe(0);
  });

  it("leaves renewal headroom by default and disables renewal when the hard lifetime is spent", async () => {
    apiMock.dynamicSecretProviders.mockResolvedValueOnce({
      capability: "F65",
      configuration_mode: "startup_static",
      configuration_changes_require_restart: true,
      secret_delivery: "file_or_secret_reference",
      supported_providers: supportedProviders,
      configured_providers: [
        {
          id: "payments-db",
          type: "postgresql",
          label: "PostgreSQL",
          allowed_roles: ["readonly-reporting"],
          maximum_ttl_seconds: 900,
          ready: true,
          configuration_revision: "runtime-revision-a",
        },
      ],
      blockers: [],
      documentation_path: "/docs/features/secrets#dynamic-secrets",
      secret_data_handling: "The browser receives readiness metadata, never provider credentials or credential-reference values.",
    });
    apiMock.previewDynamicLease.mockResolvedValueOnce({
      capability: "F65",
      operation: "issue_dynamic_secret_lease",
      ready: true,
      effect_free: true,
      provider_id: "payments-db",
      provider_type: "postgresql",
      provider_label: "PostgreSQL",
      role: "readonly-reporting",
      requested_ttl_seconds: 600,
      effective_ttl_seconds: 600,
      maximum_ttl_seconds: 900,
      configuration_revision: "runtime-revision-a",
      required_permission: "secrets:write",
      request_fingerprint: "sha256:reviewed-headroom",
      blockers: [],
      preview_writes: [],
      preview_external_effects: [],
      execute_writes: ["append one pending lease event"],
      execute_external_effects: ["create one scoped PostgreSQL credential"],
      recovery_steps: ["Revoke the lease."],
      verification_steps: ["Prove the revoked login fails."],
      cli_argv: ["trstctl", "secrets", "leases", "issue", "-f", "dynamic-secret-lease.json"],
      secret_data_handling: "Execution returns the credential once.",
    });
    currentLease = {
      id: "lease-postgres-headroom",
      provider: "payments-db",
      role: "readonly-reporting",
      state: "active",
      issued_at: "2026-06-19T13:00:00Z",
      expires_at: "2026-06-19T13:10:00Z",
      hard_expires_at: "2026-06-19T13:15:00Z",
      revocation_status: "none",
    };
    apiMock.issueDynamicLease.mockResolvedValueOnce({ ...currentLease, credential: "postgres://lease-secret-headroom" });
    apiMock.renewDynamicLease.mockImplementationOnce(async () => {
      currentLease = { ...currentLease, expires_at: "2026-06-19T13:15:00Z" };
      return { ...currentLease };
    });
    const user = userEvent.setup();
    renderSecrets("/secrets/engines");

    await user.click(await screen.findByRole("button", { name: "Open temporary credential" }));
    expect(screen.getByLabelText("Lifetime in seconds")).toHaveValue(600);
    await user.click(screen.getByRole("button", { name: "Review without creating" }));
    await waitFor(() => expect(apiMock.previewDynamicLease).toHaveBeenCalledWith({ provider: "payments-db", role: "readonly-reporting", ttl_seconds: 600 }));
    await user.click(await screen.findByRole("button", { name: "Create reviewed credential" }));
    await user.click(await screen.findByRole("button", { name: /dismiss/i }));
    expect(screen.getByText("You can extend this lease by up to 300s within its original renewal limit.")).toBeInTheDocument();
    const renew = screen.getByRole("button", { name: "Renew lease" });
    expect(renew).toBeEnabled();
    await user.click(renew);
    await waitFor(() => expect(apiMock.renewDynamicLease).toHaveBeenCalledWith("lease-postgres-headroom", { extend_seconds: 300 }));
    expect(await screen.findByText("No confirmed renewal time is available. Revoke this lease and create a new credential.")).toBeInTheDocument();
    expect(renew).toBeDisabled();
  });

  it("removes the dynamic-secret lease fixture table", () => {
    const source = readFileSync(path.join(process.cwd(), "src/pages/Secrets.tsx"), "utf8");
    expect(source).not.toMatch(/const\s+dynamicSecretRows/);
    expect(source).not.toMatch(/Dynamic secret backend fixtures/);
  });
});
