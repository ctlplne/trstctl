import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { ApiError } from "@/lib/api";
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

describe("served secrets surface", () => {
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
    apiMock.createSecret.mockResolvedValue({ name: "app/cache/token", version: 1 });
    apiMock.getSecret.mockResolvedValue({ name: "app/db/password", value: "SUPER-SECRET", version: 3 });
    apiMock.rotateSecret.mockResolvedValue({ name: "app/db/password", version: 4, updated_at: "2026-06-19T11:00:00Z" });
    apiMock.deleteSecret.mockResolvedValue(undefined);
    apiMock.issuePKISecret.mockResolvedValue({
      serial: "pki-01",
      certificate: "-----BEGIN CERTIFICATE-----\nCERT\n-----END CERTIFICATE-----",
      private_key: "-----BEGIN PRIVATE KEY-----\nKEY\n-----END PRIVATE KEY-----",
    });
    apiMock.machineLogin.mockResolvedValue({
      session_id: "sess-1",
      principal: "svc-api",
      method: "token",
      scopes: ["secrets:read", "secrets:write"],
      expires_at: "2026-06-19T13:00:00Z",
    });
    apiMock.createShare.mockResolvedValue({ token: "SHARE-TOKEN-1", expires_at: "2026-06-19T13:30:00Z" });
    apiMock.redeemShare.mockResolvedValue({ value: "redeemed-secret" });
  });

  it("lists metadata, creates, reveals, rotates, and deletes native secrets without storage writes", async () => {
    const storageSpy = vi.spyOn(Storage.prototype, "setItem");
    const user = userEvent.setup();
    renderSecrets();

    expect(await screen.findByRole("heading", { name: "Secrets" })).toBeInTheDocument();
    expect(screen.getByRole("table", { name: "Native secret metadata" })).toBeInTheDocument();
    expect(screen.getByRole("searchbox", { name: "Search native secret metadata" })).toBeInTheDocument();
    expect(screen.getByText("app/db/password")).toBeInTheDocument();
    expect(screen.getByText("native store")).toBeInTheDocument();
    expect(screen.getByText("v3")).toBeInTheDocument();
    expect(screen.getByText("Scheduled rotation and downstream sync not served yet")).toBeInTheDocument();
    expect(
      screen.getByText(/rollback-safe static rotation engine is served by API for configured backends/i),
    ).toBeInTheDocument();
    expect(screen.getByText("Auth-method administration not served yet")).toBeInTheDocument();
    expect(screen.getByText(/revoked methods aren't available in the console yet/i)).toBeInTheDocument();
    expect(screen.getByText("Secret-change approvals not served yet")).toBeInTheDocument();
    expect(screen.getByText(/Request\/approve state for sensitive secret mutations is not served yet/i)).toBeInTheDocument();
    expect(screen.queryByText("SUPER-SECRET")).not.toBeInTheDocument();

    await user.type(screen.getByRole("searchbox", { name: "Search native secret metadata" }), "cache");
    expect(screen.getByText("No secret metadata matches the current search.")).toBeInTheDocument();
    expect(screen.queryByText("app/db/password")).not.toBeInTheDocument();
    await user.clear(screen.getByRole("searchbox", { name: "Search native secret metadata" }));
    expect(screen.getByText("app/db/password")).toBeInTheDocument();

    const metadataRow = screen.getAllByRole("row", { name: /app\/db\/password/i })[0];
    await user.click(within(metadataRow).getByRole("button", { name: /view metadata/i }));
    const drawer = screen.getByRole("dialog", { name: "Secret metadata" });
    expect(within(drawer).getByText("app/db/password")).toBeInTheDocument();
    expect(within(drawer).getByText("native store")).toBeInTheDocument();
    expect(within(drawer).getByText("v3")).toBeInTheDocument();
    expect(within(drawer).queryByText("SUPER-SECRET")).not.toBeInTheDocument();
    await user.click(within(drawer).getByRole("button", { name: /close/i }));

    const createForm = within(screen.getByRole("form", { name: "Create secret" }));
    await user.type(createForm.getByLabelText("Secret name"), "app/cache/token");
    await user.type(createForm.getByLabelText("Secret value"), "new-secret-value");
    await user.click(createForm.getByRole("button", { name: /create secret/i }));

    await waitFor(() => expect(apiMock.createSecret).toHaveBeenCalledWith({ name: "app/cache/token", value: "new-secret-value" }));
    expect(await screen.findByText(/stored as version 1/i)).toBeInTheDocument();
    expect(screen.queryByText("new-secret-value")).not.toBeInTheDocument();

    const row = screen.getAllByRole("row", { name: /app\/db\/password/i })[0];
    await user.click(within(row).getByRole("button", { name: /reveal once/i }));
    expect(await screen.findByText("SUPER-SECRET")).toBeInTheDocument();

    await user.click(within(row).getByRole("button", { name: /prepare rotate/i }));
    const rotateForm = within(screen.getByRole("form", { name: "Rotate secret" }));
    await user.type(rotateForm.getByLabelText("Replacement value"), "rotated-secret");
    await user.click(rotateForm.getByRole("button", { name: /rotate secret/i }));
    await waitFor(() =>
      expect(apiMock.rotateSecret).toHaveBeenCalledWith("app/db/password", {
        name: "app/db/password",
        value: "rotated-secret",
      }),
    );
    expect(await screen.findByText(/rotated to version 4/i)).toBeInTheDocument();
    expect(screen.queryByText("rotated-secret")).not.toBeInTheDocument();

    await user.click(within(screen.getAllByRole("row", { name: /app\/db\/password/i })[0]).getByRole("button", { name: /prepare delete/i }));
    const deleteForm = within(screen.getByRole("form", { name: "Delete secret" }));
    await user.type(deleteForm.getByLabelText("Type the exact secret name"), "app/db/password");
    await user.click(deleteForm.getByRole("button", { name: /delete secret/i }));
    await waitFor(() => expect(apiMock.deleteSecret).toHaveBeenCalledWith("app/db/password"));
    expect(await screen.findByText(/deleted by the served store endpoint/i)).toBeInTheDocument();

    expect(storageSpy).not.toHaveBeenCalled();
    expect(localStorage.length).toBe(0);
    expect(sessionStorage.length).toBe(0);
  });

  it("shows developer snippets and runs an access test without rendering the value", async () => {
    const user = userEvent.setup();
    renderSecrets();
    await screen.findByText("app/db/password");

    expect(screen.getByText(/trstctl secrets get app\/db\/password/)).toBeInTheDocument();
    expect(screen.getByText(/client\.secrets\.get/)).toBeInTheDocument();
    expect(screen.queryByText("SUPER-SECRET")).not.toBeInTheDocument();

    const accessForm = within(screen.getByRole("form", { name: "Secret access test" }));
    await user.click(accessForm.getByRole("button", { name: /run access test/i }));

    await waitFor(() => expect(apiMock.getSecret).toHaveBeenCalledWith("app/db/password"));
    expect(await screen.findByText(/Access test passed for app\/db\/password/i)).toBeInTheDocument();
    expect(screen.queryByText("SUPER-SECRET")).not.toBeInTheDocument();
  });

  it("renders ephemeral API keys and dynamic leases as served while keeping scanning triage as disclosure", async () => {
    renderSecrets();
    await screen.findByText("app/db/password");

    expect(screen.getByRole("heading", { name: "Ephemeral API keys" })).toBeInTheDocument();
    expect(screen.getByText("ci/deploy preview")).toBeInTheDocument();
    expect(screen.getByText("repo:payments read, deploy:staging write")).toBeInTheDocument();
    expect(screen.getByText("15 minutes")).toBeInTheDocument();
    expect(screen.getByText(/release manager approval required/)).toBeInTheDocument();
    expect(screen.getByText("Ephemeral API-key issuance is served")).toBeInTheDocument();
    expect(screen.getByText(/POST \/api\/v1\/ephemeral\/api-keys/)).toBeInTheDocument();
    expect(screen.getByText(/trstctl-cli ephemeral api-keys issue/)).toBeInTheDocument();

    expect(screen.getByRole("heading", { name: "Code and CI secret scanning bridge" })).toBeInTheDocument();
    expect(screen.getByText("github.com/example/payments")).toBeInTheDocument();
    expect(screen.getByText("generic-api-key")).toBeInTheDocument();
    expect(screen.getByText("sha256:6e5a...91bb")).toBeInTheDocument();
    expect(screen.getAllByText(/redacted snippet/i).length).toBeGreaterThan(0);

    expect(screen.getByRole("heading", { name: "Dynamic secrets" })).toBeInTheDocument();
    expect(screen.getByText("postgresql")).toBeInTheDocument();
    expect(screen.getByText("readonly-reporting")).toBeInTheDocument();
    expect(screen.getByText("aws-iam")).toBeInTheDocument();
    expect(screen.getByText("kubernetes")).toBeInTheDocument();
    expect(screen.getByText("redis")).toBeInTheDocument();
    expect(screen.getByText("Secret-scanning triage is library-only")).toBeInTheDocument();
    expect(screen.getByText("Dynamic secret leases are served")).toBeInTheDocument();
    expect(screen.getByText(/POST \/api\/v1\/secrets\/leases/)).toBeInTheDocument();
    expect(screen.getByText(/IAM access key is deleted on revoke/i)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /issue api key|mint key|triage leak|rotate leaked|issue lease|revoke lease/i })).not.toBeInTheDocument();
  });

  it("renders transit/KMIP and secret sync fixtures without live cryptographic or sync actions", async () => {
    renderSecrets();
    await screen.findByText("app/db/password");

    expect(screen.getByRole("heading", { name: "Transit and KMIP" })).toBeInTheDocument();
    expect(screen.getByText("payments-pii")).toBeInTheDocument();
    expect(screen.getByText("encrypt/decrypt test")).toBeInTheDocument();
    expect(screen.getByText("HMAC, sign, verify")).toBeInTheDocument();
    expect(screen.getByText(/test plaintext is local-only/)).toBeInTheDocument();
    expect(screen.getByText("Transit and KMIP operations are library-only")).toBeInTheDocument();
    expect(screen.getByText(/No served transit or KMIP API\/CLI surface exists yet/i)).toBeInTheDocument();

    expect(screen.getByRole("heading", { name: "Secret sync and platform integrations" })).toBeInTheDocument();
    for (const target of ["Kubernetes", "GitHub Actions", "GitLab CI", "Terraform Cloud", "Vercel", "Netlify", "AWS Parameter Store", "Webhook"]) {
      expect(screen.getByText(target)).toBeInTheDocument();
    }
    expect(screen.getByText("secret://sync/github/prod:****")).toBeInTheDocument();
    expect(screen.getByText("Secret sync is served by API and CLI")).toBeInTheDocument();
    expect(screen.getByText(/POST \/api\/v1\/secrets\/syncs/i)).toBeInTheDocument();
    expect(screen.queryByText(/raw target token|BEGIN .* PRIVATE KEY/)).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /encrypt|decrypt|sign|verify|rewrap|sync|push|rollback/i })).not.toBeInTheDocument();
  });

  it("issues PKI secrets, tests machine login, and creates/redeems one-time shares once", async () => {
    const storageSpy = vi.spyOn(Storage.prototype, "setItem");
    apiMock.redeemShare
      .mockResolvedValueOnce({ value: "redeemed-secret" })
      .mockRejectedValueOnce(new ApiError(410, JSON.stringify({ detail: "share already redeemed" })));
    const user = userEvent.setup();
    renderSecrets();
    await screen.findByText("app/db/password");

    const pkiForm = within(screen.getByRole("form", { name: "Issue PKI secret" }));
    await user.type(pkiForm.getByLabelText("Common name"), "svc.internal");
    await user.clear(pkiForm.getByLabelText("TTL seconds"));
    await user.type(pkiForm.getByLabelText("TTL seconds"), "600");
    await user.click(pkiForm.getByRole("button", { name: /issue pki secret/i }));

    await waitFor(() => expect(apiMock.issuePKISecret).toHaveBeenCalledWith({ common_name: "svc.internal", ttl_seconds: 600 }));
    expect(await screen.findByText(/PKI bundle pki-01/i)).toBeInTheDocument();
    expect(screen.getByText(/BEGIN PRIVATE KEY/)).toBeInTheDocument();

    const loginForm = within(screen.getByRole("form", { name: "Machine login test" }));
    await user.type(loginForm.getByLabelText("Credential"), "tenant-bound-machine-token");
    await user.click(loginForm.getByRole("button", { name: /test login/i }));

    await waitFor(() => expect(apiMock.machineLogin).toHaveBeenCalledWith({ method: "token", credential: "tenant-bound-machine-token" }));
    expect(screen.getByText("sess-1")).toBeInTheDocument();
    expect(screen.getByText("svc-api")).toBeInTheDocument();
    expect(loginForm.getByLabelText("Credential")).toHaveValue("");
    expect(screen.queryByText("tenant-bound-machine-token")).not.toBeInTheDocument();

    const shareForm = within(screen.getByRole("form", { name: "Create one-time share" }));
    await user.type(shareForm.getByLabelText("Value to share"), "share-this-once");
    await user.click(shareForm.getByRole("button", { name: /create share/i }));
    await waitFor(() => expect(apiMock.createShare).toHaveBeenCalledWith({ value: "share-this-once", ttl_seconds: 300 }));
    expect(await screen.findByText("SHARE-TOKEN-1")).toBeInTheDocument();
    expect(screen.queryByText("share-this-once")).not.toBeInTheDocument();

    const redeemForm = within(screen.getByRole("form", { name: "Redeem one-time share" }));
    await user.type(redeemForm.getByLabelText("Share token"), "SHARE-TOKEN-1");
    await user.click(redeemForm.getByRole("button", { name: /redeem share/i }));
    await waitFor(() => expect(apiMock.redeemShare).toHaveBeenCalledWith({ token: "SHARE-TOKEN-1" }));
    expect(await screen.findByText("redeemed-secret")).toBeInTheDocument();

    await user.click(redeemForm.getByRole("button", { name: /redeem share/i }));
    expect(await screen.findByText("share already redeemed")).toBeInTheDocument();

    expect(storageSpy).not.toHaveBeenCalled();
    expect(localStorage.length).toBe(0);
    expect(sessionStorage.length).toBe(0);
  });

  it("shows the served fail-closed disabled state when secrets API or KEK is unavailable", async () => {
    apiMock.secretPage.mockRejectedValueOnce(new ApiError(503, JSON.stringify({ detail: "secrets.enable_api disabled or KEK missing" })));
    renderSecrets();

    expect(await screen.findByText("Secrets API unavailable or disabled")).toBeInTheDocument();
    expect(screen.getByText(/secrets.enable_api disabled or KEK missing/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /create secret/i })).toBeDisabled();
  });

  it("renders the shared grid empty state for an enabled store with no metadata", async () => {
    apiMock.secretPage.mockResolvedValueOnce({ items: [] });
    renderSecrets();

    expect(await screen.findByText("No secrets stored yet")).toBeInTheDocument();
    expect(screen.getByText(/Only the name and version return/)).toBeInTheDocument();
  });
});
