import { describe, it, expect, vi, beforeEach } from "vitest";
import { cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { ApiError } from "@/lib/api";
import type { CapabilityView, CapabilityViewItem } from "@/lib/api-types.gen";
import { CapabilityFixtureProvider } from "@/lib/capabilities";
import { AppQueryProvider } from "@/lib/query";
import { Secrets } from "@/pages/Secrets";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    secretPage: vi.fn(),
    previewSecretAccess: vi.fn(),
    previewSecretCreate: vi.fn(),
    createSecret: vi.fn(),
    getSecret: vi.fn(),
    getSecretWithToken: vi.fn(),
    rotateSecret: vi.fn(),
    previewSecretRotation: vi.fn(),
    runSecretRotation: vi.fn(),
    createSecretRotationSchedule: vi.fn(),
    secretRotationSchedules: vi.fn(),
    runDueSecretRotations: vi.fn(),
    deleteSecret: vi.fn(),
    approvalRequests: vi.fn(),
    approveSecretChange: vi.fn(),
    previewPKISecret: vi.fn(),
    issuePKISecret: vi.fn(),
    previewMachineLogin: vi.fn(),
    machineLogin: vi.fn(),
    previewShare: vi.fn(),
    createShare: vi.fn(),
    redeemShare: vi.fn(),
    previewEphemeralAPIKey: vi.fn(),
    issueEphemeralAPIKey: vi.fn(),
    verifyEphemeralAPIKey: vi.fn(),
    dynamicSecretProviders: vi.fn(),
    previewDynamicLease: vi.fn(),
    issueDynamicLease: vi.fn(),
    renewDynamicLease: vi.fn(),
    revokeDynamicLease: vi.fn(),
    transitKeys: vi.fn(),
    transitKeyVersions: vi.fn(),
    transitPosture: vi.fn(),
    createTransitKey: vi.fn(),
    rotateTransitKey: vi.fn(),
    encryptTransit: vi.fn(),
    decryptTransit: vi.fn(),
    hmacTransit: vi.fn(),
    rewrapTransit: vi.fn(),
    signTransit: vi.fn(),
    verifyTransit: vi.fn(),
    auditEvents: vi.fn(),
    secretRepositoryScanning: vi.fn(),
    thirdPartySecretScanning: vi.fn(),
    ingestThirdPartySecretScan: vi.fn(),
    cloudSecretManagers: vi.fn(),
    secretSyncTargets: vi.fn(),
    kubernetesSecretOperator: vi.fn(),
    secretWorkloadInjection: vi.fn(),
    unvaultedSecrets: vi.fn(),
    previewSecretScan: vi.fn(),
    scanSecrets: vi.fn(),
    syncSecret: vi.fn(),
    identities: vi.fn(),
    apiTokens: vi.fn(),
    createAPIToken: vi.fn(),
    revokeAPIToken: vi.fn(),
    machineAuthMethods: vi.fn(),
    machineSessions: vi.fn(),
    revokeMachineSession: vi.fn(),
    disableMachineAuthMethod: vi.fn(),
    enableMachineAuthMethod: vi.fn(),
    owners: vi.fn(),
  },
}));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: apiMock };
});

/** S-C2: the workspaces are routes; tests mount the page at the route under
 * test instead of clicking the retired in-page tab strip. */
function renderSecrets(path = "/secrets") {
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

const nativeStoreUnavailableDetail =
  "The native secret store is turned off in this deployment. Enable it before storing, revealing, rotating, sharing, or leasing application secrets.";

function secretsCapabilityItem(capabilityId: "F37" | "F58" | "F63", operations: string[], available: boolean): CapabilityViewItem {
  return {
    capability_id: capabilityId,
    name: `Fixture ${capabilityId}`,
    purpose: "Prove that the page obeys exact runtime readiness before making an optional request.",
    tool: "secrets",
    classification: "primary",
    console_route: "/secrets",
    maturity: "partial_workflow",
    release_blocking: true,
    edition: "core",
    runtime_state: available ? "available" : "unavailable",
    authorization_state: available ? "full" : "none",
    dependency_state: "none",
    dependencies: [],
    stages: [{ name: "observe", completion: available ? "complete" : "blocked", ...(available ? {} : { reason: nativeStoreUnavailableDetail }) }],
    actions: {
      allowed: available ? operations : [],
      scoped: [],
      denied: [],
      unavailable: available
        ? []
        : operations.map((operation_id) => ({ operation_id, code: "dependency_not_configured" as const, detail: nativeStoreUnavailableDetail })),
    },
  };
}

function secretsRuntime(available: boolean): CapabilityView {
  return {
    schema_version: 2,
    contract_schema_version: 3,
    enforcement_note: "The server checks every operation again when it executes.",
    license: { tier: "community", state: "community" },
    operations: [],
    items: [
      secretsCapabilityItem("F63", ["listSecrets"], available),
      secretsCapabilityItem("F37", ["listSecretRotationSchedules"], available),
      secretsCapabilityItem("F58", ["listMachineAuthMethods", "listMachineSessions"], available),
    ],
  };
}

function renderSecretsWithRuntime(view: CapabilityView, path = "/secrets") {
  return render(
    <CapabilityFixtureProvider view={view}>
      <MemoryRouter initialEntries={[path]}>
        <AppQueryProvider>
          <Routes>
            <Route path="/secrets" element={<Secrets />} />
            <Route path="/secrets/:workspace" element={<Secrets />} />
          </Routes>
        </AppQueryProvider>
      </MemoryRouter>
    </CapabilityFixtureProvider>,
  );
}

function scheduledRunFixture(index: number) {
  const suffix = String(index + 1).padStart(12, "0");
  return {
    schedule_id: `88888888-8888-4888-8888-${suffix}`,
    run_id: `11111111-1111-4111-8111-${suffix}`,
    status: "failed",
    rotation: {
      key: index === 0 ? "app/partial/password" : `app/partial/${index}`,
      old_ref: "version:3",
      new_ref: "",
      completed: false,
      queued: false,
      rolled_back: false,
      rollback_attempted: false,
      rollback_failed: false,
      error: "scheduled rotation failed",
    },
    error: "scheduled rotation failed",
    ran_at: "2026-06-19T10:01:00Z",
    reconciled: false,
  };
}

function primeSecretsMocks() {
  localStorage.clear();
  sessionStorage.clear();
  vi.restoreAllMocks();
  for (const mock of Object.values(apiMock)) mock.mockReset();
  apiMock.secretPage.mockResolvedValue({
    items: [
      {
        name: "app/db/password",
        owner_id: "11111111-1111-4111-8111-111111111111",
        version: 3,
        created_at: "2026-06-18T10:00:00Z",
        updated_at: "2026-06-19T10:00:00Z",
      },
    ],
  });
  apiMock.createSecret.mockResolvedValue({
    name: "app/cache/token",
    owner_id: "11111111-1111-4111-8111-111111111111",
    version: 1,
  });
  apiMock.previewSecretCreate.mockResolvedValue({
    capability: "F63",
    operation: "create",
    ready: true,
    effect_free: true,
    name: "app/cache/token",
    owner_id: "11111111-1111-4111-8111-111111111111",
    next_version: 1,
    required_permission: "secrets:write",
    request_fingerprint: "sha256:f63-create-preview-fixture",
    blockers: [],
    preview_writes: [],
    preview_external_effects: [],
    execute_writes: ["append secret.created", "project sealed version 1"],
    execute_external_effects: [],
    recovery_steps: ["Cancel before execution", "Delete the created secret if it is no longer required"],
    secret_data_handling: "The value is validated in transient memory and is never echoed, logged, or stored by preview.",
  });
  apiMock.previewSecretAccess.mockResolvedValue({
    capability: "F64",
    operation: "read_for_process",
    ready: true,
    effect_free: true,
    name: "app/db/password",
    version: 3,
    env_var: "DB_PASSWORD",
    resolve_references: false,
    required_permission: "secrets:read",
    request_fingerprint: "sha256:f64-access-preview-fixture",
    blockers: [],
    preview_reads: ["read one tenant-scoped secret metadata row", "open the selected value in transient memory and wipe it after validation"],
    preview_writes: [],
    preview_external_effects: [],
    execute_reads: ["GET the selected tenant-scoped secret through the served SDK path"],
    execute_data_flow: ["return the value only to this authorized caller"],
    recovery_steps: ["Keep this reviewed plan and retry after restoring the dependency."],
    verification_steps: ["Confirm the response name and version match this plan."],
    cli_argv: ["trstctl", "run", "--secret", "DB_PASSWORD=app/db/password", "--", "./service"],
    api_request: { method: "GET", path: "/api/v1/secrets/store/app/db/password" },
    typescript:
      'const secret = await client.secrets.get("app/db/password", { resolve: false });\nprocess.env["DB_PASSWORD"] = secret.value; // memory only; never log or persist',
    bulk_import: {
      available: false,
      reason: "Atomic event-sourced bulk import is not implemented, so the compatibility route fails closed with 501.",
      safe_path: "Create each secret with its own idempotency key.",
    },
    secret_data_handling: "The plan contains metadata only and never returns the secret value.",
  });
  apiMock.owners.mockResolvedValue([
    {
      id: "11111111-1111-4111-8111-111111111111",
      tenant_id: "t1",
      kind: "service",
      name: "Payments platform",
      environment: "production",
      email: "",
      created_at: "2026-06-01T00:00:00Z",
      escalation_chain: [],
      ownership_complete: true,
      ownership_attested: true,
      ownership_current: true,
    },
  ]);
  apiMock.getSecret.mockResolvedValue({ name: "app/db/password", value: "SUPER-SECRET", version: 3 });
  apiMock.getSecretWithToken.mockResolvedValue({ name: "app/db/password", value: "WORKLOAD-SECRET", version: 3 });
  apiMock.rotateSecret.mockResolvedValue({ name: "app/db/password", version: 4, updated_at: "2026-06-19T11:00:00Z" });
  apiMock.previewSecretRotation.mockImplementation(async (input: { provider: string; key: string; old_ref: string; target?: string; remote_key?: string }) => ({
    capability: "F37",
    ready: input.provider.startsWith("connector:"),
    effect_free: true,
    provider: input.provider,
    key: input.key,
    old_ref: input.old_ref,
    target: input.target || input.provider.replace(/^connector:/, ""),
    remote_key: input.remote_key || input.key,
    current_version: 3,
    next_version: 4,
    required_permission: "secrets:write",
    request_fingerprint: "sha256:f37-preview-fixture",
    blockers: input.provider.startsWith("connector:") ? [] : ["This provider does not yet have a durable worker-owned rotation path."],
    preview_writes: [],
    preview_external_effects: [],
    execute_writes: ["append one immutable event", "project one sealed successor", "commit one connector outbox intent"],
    execute_external_effects: ["deliver the successor to the connector target"],
    recovery_steps: ["retry the same command", "inspect delivery evidence", "recover the predecessor version"],
    secret_data_handling: "Preview reads metadata only and never decrypts or sends secret material.",
  }));
  apiMock.runSecretRotation.mockResolvedValue({
    key: "app/db/password",
    old_ref: "version:3",
    new_ref: "version:4",
    completed: false,
    queued: true,
    rolled_back: false,
    rollback_attempted: false,
    rollback_failed: false,
  });
  apiMock.createSecretRotationSchedule.mockResolvedValue({
    id: "77777777-7777-7777-7777-777777777777",
    name: "daily",
    provider: "connector:ci",
    key: "app/db/password",
    old_ref: "version:3",
    interval_seconds: 86400,
    enabled: true,
    next_run_at: "2026-06-20T10:00:00Z",
    last_run_status: "",
  });
  apiMock.secretRotationSchedules.mockResolvedValue({ items: [] });
  apiMock.runDueSecretRotations.mockResolvedValue({
    ran: 50,
    scanned: 51,
    runs: Array.from({ length: 50 }, (_, index) => scheduledRunFixture(index)),
    deferred: [
      {
        schedule_id: "77777777-7777-7777-7777-777777777777",
        reason: "approval_pending",
        due_at: "2026-06-19T10:00:00Z",
        error: "scheduled rotation is waiting for approval",
      },
    ],
    run_limit_reached: true,
    scan_limit_reached: false,
    complete: false,
    partial: false,
  });
  apiMock.deleteSecret.mockResolvedValue(undefined);
  apiMock.approvalRequests.mockResolvedValue([]);
  apiMock.approveSecretChange.mockResolvedValue({
    resource: "secret:app/db/password",
    action: "rotate",
    approver: "bob",
    approvals: 2,
  });
  apiMock.previewPKISecret.mockResolvedValue({
    capability: "F67",
    operation: "issue_certificate",
    ready: true,
    effect_free: true,
    custody_mode: "requester_csr",
    common_name: "svc.internal",
    dns_names: ["svc.internal"],
    requested_ttl_seconds: 900,
    effective_ttl_seconds: 900,
    profile: "secrets-api",
    ca_certificate_sha256: "sha256:ca",
    csr_sha256: "sha256:csr",
    subject_key_algorithm: "ECDSA",
    subject_key_bits: 256,
    required_permission: "secrets:write",
    request_fingerprint: "sha256:reviewed-default",
    vault_path: "/v1/pki/sign/default",
    prerequisites: [
      { id: "issuing_ca", ready: true, detail: "Issuing CA connected." },
      { id: "revocation_tracking", ready: true, detail: "Revocation tracking connected." },
    ],
    blockers: [],
    preview_writes: [],
    preview_external_effects: [],
    execute_writes: ["record the issued serial"],
    execute_external_effects: ["ask the signer to sign one certificate"],
    recovery_steps: ["revoke the exact issued serial"],
    verification_steps: ["verify the returned certificate"],
    cli_argv: ["trstctl", "secrets", "pki", "-f", "pki-request.json"],
    secret_data_handling: "The private key stays with the requester.",
  });
  apiMock.issuePKISecret.mockResolvedValue({
    serial: "pki-01",
    certificate: "-----BEGIN CERTIFICATE-----\nCERT\n-----END CERTIFICATE-----",
    private_key: "-----BEGIN PRIVATE KEY-----\nKEY\n-----END PRIVATE KEY-----",
  });
  // C-S1 grant-console rosters and ledger defaults.
  apiMock.identities.mockResolvedValue([
    { id: "wl-1111", name: "payments-bot", kind: "workload_identity", status: "issued" },
    { id: "id-2222", name: "billing-svc", kind: "x509_certificate", status: "issued" },
  ]);
  apiMock.apiTokens.mockResolvedValue({
    items: [
      { id: "tok-1", tenant_id: "t1", subject: "wl-1111", scopes: ["secrets:read"], created_at: "2026-07-01T00:00:00Z" },
      { id: "tok-2", tenant_id: "t1", subject: "old-bot", scopes: ["secrets:read"], created_at: "2026-06-01T00:00:00Z", revoked_at: "2026-06-20T00:00:00Z" },
    ],
  });
  apiMock.createAPIToken.mockResolvedValue({
    id: "tok-3",
    tenant_id: "t1",
    subject: "wl-1111",
    scopes: ["secrets:read"],
    token: "trst_REVEAL_ONCE_abc",
    created_at: "2026-07-14T00:00:00Z",
  });
  apiMock.revokeAPIToken.mockResolvedValue(undefined);
  // C-S4 auth-method console defaults.
  apiMock.machineAuthMethods.mockResolvedValue({
    items: [
      { name: "token", type: "token", source: "builtin", jwks_configured: false },
      {
        name: "ci-jwt",
        type: "jwt",
        source: "config",
        issuer: "https://ci.example.test",
        audience: "trstctl",
        scopes: ["secrets:read"],
        jwks_configured: true,
        disabled: true,
      },
    ],
  });
  apiMock.machineSessions.mockResolvedValue({
    items: [
      {
        id: "sess-active-1",
        principal: "payments-bot",
        method: "token",
        scopes: ["secrets:read"],
        status: "active",
        issued_at: "2026-07-14T00:00:00Z",
        expires_at: "2026-07-14T01:00:00Z",
      },
      {
        id: "sess-revoked-1",
        principal: "retired-bot",
        method: "token",
        status: "revoked",
        issued_at: "2026-07-01T00:00:00Z",
        expires_at: "2026-07-01T01:00:00Z",
        revoked_at: "2026-07-01T00:30:00Z",
        revoked_by: "operator-1",
      },
    ],
  });
  apiMock.revokeMachineSession.mockResolvedValue({
    id: "sess-active-1",
    principal: "payments-bot",
    method: "token",
    status: "revoked",
    issued_at: "2026-07-14T00:00:00Z",
    expires_at: "2026-07-14T01:00:00Z",
  });
  apiMock.disableMachineAuthMethod.mockResolvedValue({ name: "token", disabled: true });
  apiMock.enableMachineAuthMethod.mockResolvedValue({ name: "ci-jwt", disabled: false });
  apiMock.previewMachineLogin.mockResolvedValue({
    capability: "F58",
    operation: "test_machine_login",
    ready: true,
    effect_free: true,
    method: { name: "token", type: "token", source: "builtin", jwks_configured: false, disabled: false },
    tenant_binding: "The credential and issued session are bound to this tenant.",
    credential_format: "A tenant-, audience-, and expiry-bound machine token.",
    session_ttl_seconds: 3600,
    required_permission: "secrets:read",
    request_fingerprint: "sha256:reviewed-machine-login",
    prerequisites: [
      { id: "method_configured", ready: true, detail: "The token method is configured." },
      { id: "method_enabled", ready: true, detail: "The token method accepts new logins." },
      { id: "session_ledger", ready: true, detail: "Issued sessions are recorded durably." },
    ],
    blockers: [],
    preview_reads: ["read the tenant-scoped method projection"],
    preview_writes: [],
    preview_external_effects: [],
    execute_writes: ["append one session-issued event", "project one tenant-scoped session ledger row"],
    execute_external_effects: [],
    recovery_steps: ["Correct the tenant, audience, expiry, or method input, then try again."],
    verification_steps: [
      "Confirm the returned method, principal, scopes, and expiry match the reviewed plan.",
      "Confirm the session appears in Issued sessions.",
    ],
    cli_argv: ["trstctl", "secrets", "login", "-f", "machine-login.json"],
    secret_data_handling: "Preview never receives a credential. Execution consumes it once, never echoes it, and clears the browser field after every attempt.",
  });
  apiMock.machineLogin.mockResolvedValue({
    session_id: "sess-1",
    principal: "svc-api",
    method: "token",
    scopes: ["secrets:read", "secrets:write"],
    expires_at: "2026-06-19T13:00:00Z",
    token: "trst_MACHINE_SESSION_REVEAL_ONCE",
  });
  apiMock.createShare.mockResolvedValue({ token: "SHARE-TOKEN-1", expires_at: "2026-06-19T13:30:00Z" });
  apiMock.previewShare.mockResolvedValue({
    capability: "F60",
    operation: "create_one_time_share",
    ready: true,
    effect_free: true,
    requested_ttl_seconds: 300,
    effective_ttl_seconds: 300,
    required_permission: "secrets:write",
    request_fingerprint: "sha256:reviewed-share",
    sensitive_change_approval_configured: true,
    blockers: [],
    preview_writes: [],
    preview_external_effects: [],
    execute_writes: ["store one sealed share and its token hash", "append plaintext-free audit evidence"],
    execute_external_effects: [],
    recovery_steps: ["Retry with the same recovery key after an ambiguous response."],
    verification_steps: ["Redeem once; confirm a second redeem fails closed."],
    cli_argv: ["trstctl", "secrets", "shares", "create", "-f", "share-request.json"],
    secret_data_handling: "Preview never receives the value. Execution seals it and returns the bearer token once.",
  });
  apiMock.redeemShare.mockResolvedValue({ value: "redeemed-secret" });
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
  apiMock.dynamicSecretProviders.mockResolvedValue({
    capability: "F65",
    configuration_mode: "startup_static",
    configuration_changes_require_restart: true,
    secret_delivery: "file_or_secret_reference",
    supported_providers: ["postgresql", "mysql", "mongodb", "aws-iam", "gcp-iam", "azure-entra", "kubernetes", "redis"].map((type) => ({
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
    })),
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
  apiMock.issueDynamicLease.mockResolvedValue({
    id: "lease-postgres-1",
    provider: "payments-db",
    role: "readonly-reporting",
    state: "active",
    issued_at: "2026-06-19T13:00:00Z",
    expires_at: "2026-06-19T13:20:00Z",
    credential: "postgres://lease-secret",
  });
  apiMock.renewDynamicLease.mockResolvedValue({
    id: "lease-postgres-1",
    provider: "payments-db",
    role: "readonly-reporting",
    state: "active",
    issued_at: "2026-06-19T13:00:00Z",
    expires_at: "2026-06-19T13:25:00Z",
  });
  apiMock.revokeDynamicLease.mockResolvedValue({
    id: "lease-postgres-1",
    provider: "payments-db",
    role: "readonly-reporting",
    state: "revoked",
    issued_at: "2026-06-19T13:00:00Z",
    expires_at: "2026-06-19T13:25:00Z",
  });
  apiMock.transitKeys.mockResolvedValue({ items: [] });
  apiMock.transitKeyVersions.mockImplementation(async (name: string) => ({
    name,
    kind: name.includes("signing") ? "sign" : name.includes("integrity") ? "hmac" : "aead",
    versions: [
      { version: 1, current: false },
      { version: 2, current: true },
    ],
  }));
  apiMock.transitPosture.mockResolvedValue({
    checked_at: "2026-09-03T12:00:00Z",
    effect_free: true,
    transit: {
      served: true,
      persistence_configured: true,
      restore_state: "restored",
      recovery_ready: true,
      detail: "The running service restored its sealed keyring during startup.",
    },
    kmip: {
      state: "not_configured",
      configured: false,
      served: false,
      listening: false,
      tenant_bound: false,
      transport: "mTLS",
      profile: "KMIP 1.x AES-256 SymmetricKey appliance profile",
      objects: ["AES-256 SymmetricKey"],
      operations: ["Create", "Get", "Locate", "Revoke", "Destroy"],
      detail: "KMIP is not configured for this tenant.",
      recovery: "Enable the licensed KMIP listener and bind it to this tenant.",
    },
    recovery_steps: ["Keep the original ciphertext.", "Repair the original KEK or mount.", "Retry and prove the result."],
    proof: ["Effect-free.", "No keyring read.", "No key bytes returned."],
  });
  apiMock.createTransitKey.mockImplementation(async (input: { name: string; kind: string }) => ({ ...input, version: 1 }));
  apiMock.rotateTransitKey.mockImplementation(async (input: { name: string }) => ({
    name: input.name,
    kind: input.name.includes("integrity") ? "hmac" : input.name.includes("signing") ? "sign" : "aead",
    version: 2,
  }));
  apiMock.encryptTransit.mockResolvedValue({ ciphertext: "trst:v1:ciphertext", version: 4 });
  apiMock.decryptTransit.mockResolvedValue({ plaintext: "aGVsbG8gdHJhbnNpdA==" });
  apiMock.hmacTransit.mockResolvedValue({ hmac: "hmac-base64" });
  apiMock.rewrapTransit.mockResolvedValue({ ciphertext: "trst:v4:rewrapped", version: 4 });
  apiMock.signTransit.mockResolvedValue({ signature: "signature-base64", public_der: "public-der-base64" });
  apiMock.verifyTransit.mockResolvedValue({ valid: true });
  apiMock.auditEvents.mockResolvedValue([{ sequence: 42, tenant_id: "tenant-a", time: "2026-09-03T12:00:00Z", type: "transit.key.rotated" }]);
  apiMock.secretRepositoryScanning.mockResolvedValue(repoScanPostureFixture());
  apiMock.thirdPartySecretScanning.mockResolvedValue(thirdPartyScanPostureFixture());
  apiMock.ingestThirdPartySecretScan.mockResolvedValue({
    capability: "CAP-SCAN-04",
    provider: "slack",
    source: "acme/slack",
    source_id: "secret-third-party:slack:acme-slack",
    run_id: "66666666-6666-6666-6666-666666666666",
    queued: true,
    status: "queued",
    outbox_destination: "discovery.run",
    scanner: "gitleaks v8.27.2",
    discovery_run_path: "/api/v1/discovery/runs/66666666-6666-6666-6666-666666666666",
  });
  apiMock.cloudSecretManagers.mockResolvedValue(cloudSecretManagerFixture());
  apiMock.secretSyncTargets.mockResolvedValue(syncTargetCatalogFixture());
  apiMock.kubernetesSecretOperator.mockResolvedValue(kubernetesSecretOperatorFixture());
  apiMock.secretWorkloadInjection.mockResolvedValue(secretWorkloadInjectionFixture());
  apiMock.unvaultedSecrets.mockResolvedValue(unvaultedSecretPostureFixture());
  apiMock.previewSecretScan.mockResolvedValue(secretScanPreviewFixture());
  apiMock.scanSecrets.mockResolvedValue({
    run_id: "55555555-5555-5555-5555-555555555555",
    scanner: "gitleaks",
    engine_version: "8.18.2",
    mode: "workspace",
    custom_rules: false,
    capabilities: ["pattern-rules", "entropy-rules", "default-rules-100-plus", "workspace"],
    rules_active: 121,
    findings_count: 1,
    findings: [{ rule_id: "generic-api-key", file: "config/ci.yml", line: 42, credential_ref: "sha256:6e5a...91bb" }],
  });
  apiMock.syncSecret.mockResolvedValue({
    name: "app/db/password",
    target: "kubernetes/prod",
    remote_key: "Secret/payments-db/password",
    enqueued: true,
    delivered: false,
  });
}

function repoScanPostureFixture() {
  return {
    capability: "CAP-SCAN-01",
    served: true,
    generated_at: "2026-06-29T00:00:00Z",
    scanner: "gitleaks v8.27.2",
    minimum_rules_active: 140,
    providers: [
      {
        id: "github",
        name: "GitHub",
        realtime_triggers: ["push", "pull_request"],
        auth_mode: "authenticated webhook",
        ingest_mode: "normalized GitHub event queues secret_repo discovery",
        ref_types: ["branch", "commit_sha"],
        secret_handling: "redacted metadata only",
        outbox_mode: "discovery.run outbox",
      },
      {
        id: "gitlab",
        name: "GitLab",
        realtime_triggers: ["push", "merge_request"],
        auth_mode: "authenticated webhook",
        ingest_mode: "normalized GitLab event queues secret_repo discovery",
        ref_types: ["branch", "commit_sha"],
        secret_handling: "redacted metadata only",
        outbox_mode: "discovery.run outbox",
      },
      {
        id: "bitbucket",
        name: "Bitbucket",
        realtime_triggers: ["repo:push", "pullrequest:updated"],
        auth_mode: "authenticated webhook",
        ingest_mode: "normalized Bitbucket event queues secret_repo discovery",
        ref_types: ["branch", "commit_sha"],
        secret_handling: "redacted metadata only",
        outbox_mode: "discovery.run outbox",
      },
    ],
    webhook_paths: [
      "/api/v1/secrets/scans/repositories/github/webhook",
      "/api/v1/secrets/scans/repositories/gitlab/webhook",
      "/api/v1/secrets/scans/repositories/bitbucket/webhook",
    ],
    queue_model: "authenticated provider webhook records a tenant-scoped discovery run",
    redaction_model: "rule/file/line only",
    event_flow: ["discovery.source.upserted", "discovery.run.queued", "discovery.finding.recorded", "discovery.run.completed"],
    release_gates: [
      { id: "provider-webhook-contract", command: "go test", artifact: "repo-secret-scan-contract", required: true },
      { id: "architecture-lint", command: "make lint test", artifact: "local gate transcript", required: true },
    ],
    operator_actions: ["install provider webhooks"],
    residuals: ["native provider signature verification remains a follow-up"],
    evidence_refs: ["internal/api/secrets.go"],
    architecture_controls: ["AN-2", "AN-5", "AN-6", "AN-8"],
  };
}

function secretScanPreviewFixture() {
  return {
    capability: "F39",
    operation: "run_secret_scan",
    ready: true,
    effect_free: true,
    target_path: "github.com/example/payments",
    mode: "workspace",
    custom_rules: false,
    scanner: "gitleaks v8.27.2",
    rules_active: 213,
    capabilities: ["pattern-rules", "entropy-rules", "default-rules-100-plus", "workspace"],
    required_permission: "secrets:write",
    request_fingerprint: "sha256:reviewed-f39",
    blockers: [],
    prerequisites: ["The target must stay inside an operator-configured scan root."],
    preview_writes: [],
    preview_external_effects: [],
    execute_writes: ["append tenant-scoped discovery events"],
    execute_external_effects: ["start the pinned Gitleaks process with redaction enabled"],
    recovery_steps: ["Retry the identical reviewed request with the same Idempotency-Key."],
    verification_steps: ["Open the returned discovery run and confirm its completed state."],
    cli_argv: ["trstctl", "secrets", "scans", "preview", "-f", "secret-scan.json"],
    secret_data_handling: "Matched secret values are dropped before events, API responses, logs, or evidence are created.",
  };
}

function thirdPartyScanPostureFixture() {
  return {
    capability: "CAP-SCAN-04",
    served: true,
    generated_at: "2026-06-29T00:00:00Z",
    scanner: "gitleaks v8.27.2",
    minimum_rules_active: 140,
    providers: [
      {
        id: "cicd_log",
        name: "CI/CD logs",
        artifact_kinds: ["workflow log", "job trace"],
        ingest_mode: "artifact path queues secret_third_party discovery",
        secret_handling: "raw logs stay outside trstctl; redacted metadata only",
        outbox_mode: "discovery.run outbox",
      },
      {
        id: "container_registry",
        name: "Container registries",
        artifact_kinds: ["manifest", "layer metadata"],
        ingest_mode: "artifact path queues secret_third_party discovery",
        secret_handling: "raw registry artifacts stay outside trstctl",
        outbox_mode: "discovery.run outbox",
      },
      {
        id: "slack",
        name: "Slack",
        artifact_kinds: ["export jsonl", "message transcript"],
        ingest_mode: "artifact path queues secret_third_party discovery",
        secret_handling: "raw chat exports stay outside trstctl",
        outbox_mode: "discovery.run outbox",
      },
      {
        id: "jira",
        name: "Jira",
        artifact_kinds: ["issue export", "attachment manifest"],
        ingest_mode: "artifact path queues secret_third_party discovery",
        secret_handling: "raw issue exports stay outside trstctl",
        outbox_mode: "discovery.run outbox",
      },
    ],
    ingest_paths: [
      "/api/v1/secrets/scans/third-party/cicd_log/ingest",
      "/api/v1/secrets/scans/third-party/container_registry/ingest",
      "/api/v1/secrets/scans/third-party/slack/ingest",
      "/api/v1/secrets/scans/third-party/jira/ingest",
    ],
    queue_model: "artifact-path ingest records a tenant-scoped discovery run",
    redaction_model: "rule/file/line and credential_ref only",
    event_flow: ["discovery.source.upserted", "discovery.run.queued", "discovery.finding.recorded", "discovery.run.completed"],
    release_gates: [
      { id: "third-party-artifact-contract", command: "go test", artifact: "cap-scan-04-contract", required: true },
      { id: "architecture-lint", command: "make lint test", artifact: "local gate transcript", required: true },
    ],
    operator_actions: ["export CI log, registry, Slack, or Jira artifacts to a scanner-readable path"],
    residuals: ["native provider API polling and signature verification remain follow-ups"],
    evidence_refs: ["internal/api/secrets.go", "internal/server/discovery.go"],
    architecture_controls: ["AN-2", "AN-5", "AN-6", "AN-8"],
  };
}

function syncTargetCatalogFixture() {
  const targets: Array<[string, string, string]> = [
    ["aws-secrets-manager", "AWS Secrets Manager", "aws"],
    ["gcp-secret-manager", "GCP Secret Manager", "gcp"],
    ["azure-key-vault", "Azure Key Vault", "azure"],
    ["github-actions", "GitHub Actions", "github"],
    ["gitlab-ci", "GitLab CI", "gitlab"],
    ["vercel-netlify", "Vercel", "vercel"],
    ["ci", "Generic CI secret endpoint", "ci"],
  ];
  return {
    capability: "CAP-SECR-03",
    served: true,
    generated_at: "2026-06-29T00:00:00Z",
    configured_targets: targets.map(([id]) => id),
    outbox_mode: "sealed PostgreSQL outbox",
    evidence_refs: ["internal/secretsync/pushers.go"],
    residuals: ["operator config required"],
    targets: targets.map(([id, name, platform]) => ({
      id,
      name,
      platform,
      configured: true,
      delivery_mode: `${name} delivery`,
      auth_mode: "operator token",
      wire_format: "base64 payload",
      secret_handling: "metadata only",
      capabilities: ["outbox-delivery"],
    })),
  };
}

function cloudSecretManagerFixture() {
  return {
    capability: "CAP-SEC-04",
    served: true,
    generated_at: "2026-06-29T00:00:00Z",
    summary: {
      total_providers: 4,
      discovery_supported: 4,
      discovery_configured: 4,
      sync_supported: 3,
      sync_configured: 3,
      fully_configured: 4,
      configured_connections: 7,
    },
    configured_providers: ["aws-secrets-manager", "azure-key-vault", "gcp-secret-manager", "hashicorp-vault"],
    configured_sync_targets: ["aws-secrets-manager", "azure-key-vault", "gcp-secret-manager"],
    discovery_mode: "tenant-scoped cloud_secret source execution",
    outbox_mode: "sealed PostgreSQL outbox",
    secret_handling: "metadata only",
    architecture_controls: ["AN-1", "AN-2", "AN-5", "AN-6", "AN-8"],
    evidence_refs: ["internal/api/secrets.go", "internal/server/secrets_sync_served_test.go"],
    residuals: ["operator config required"],
    recommended_next_actions: ["configure cloud_secret sources"],
    providers: [
      ["aws-secrets-manager", "AWS Secrets Manager", "aws", true, true],
      ["gcp-secret-manager", "GCP Secret Manager", "gcp", true, true],
      ["azure-key-vault", "Azure Key Vault", "azure", true, true],
      ["hashicorp-vault", "HashiCorp Vault KV", "vault", true, false],
    ].map(([id, name, platform, discoveryConfigured, syncConfigured]) => ({
      id,
      name,
      platform,
      discovery_supported: true,
      discovery_configured: Boolean(discoveryConfigured),
      discovery_source_kind: "cloud_secret",
      discovery_source_count: 1,
      discovery_read_ops: ["GET only"],
      sync_supported: id !== "hashicorp-vault",
      sync_configured: Boolean(syncConfigured),
      sync_target_id: id === "hashicorp-vault" ? "" : String(id),
      sync_write_operation: id === "hashicorp-vault" ? "" : "provider write",
      secret_handling: "secret values are byte-backed and never rendered",
      capabilities: ["cloud-secret-manager"],
      evidence_refs: ["internal/secretsync/pushers.go"],
    })),
  };
}

function kubernetesSecretOperatorFixture() {
  return {
    capability: "CAP-SECR-04",
    served: true,
    generated_at: "2026-06-29T00:00:00Z",
    crds: [
      {
        kind: "TrstctlSecretSync",
        api_group: "trstctl.com",
        api_version: "trstctl.com/v1alpha1",
        plural: "trstctlsecretsyncs",
        status: "served",
        owns: ["Kubernetes Secret data", "status.contentHash"],
        evidence_ref: "deploy/operator/crd.yaml",
      },
      {
        kind: "TrstctlControlPlane",
        api_group: "trstctl.com",
        api_version: "trstctl.com/v1alpha1",
        plural: "trstctlcontrolplanes",
        status: "served",
        owns: ["control-plane Deployment"],
        evidence_ref: "deploy/operator/crd.yaml",
      },
    ],
    sync_flow: ["resolve through served secret store", "write Kubernetes Secret", "patch workload templates"],
    reload_workloads: ["Deployment", "StatefulSet", "DaemonSet"],
    secret_handling: "operator reads resolved values as bytes and reports metadata only",
    architecture_controls: ["control-plane token from Secret reference"],
    evidence_refs: ["internal/operator/secretsync.go", "deploy/operator/crd.yaml"],
    residuals: ["operator still uses a polling reconcile loop rather than a shared informer/workqueue controller"],
    recommended_next_actions: ["move to informer-backed queues"],
  };
}

function secretWorkloadInjectionFixture() {
  return {
    capability: "CAP-SECR-05",
    served: true,
    generated_at: "2026-06-30T00:00:00Z",
    crd: {
      kind: "TrstctlSecretInjection",
      api_group: "trstctl.com",
      api_version: "trstctl.com/v1alpha1",
      plural: "trstctlsecretinjections",
      status: "served",
      owns: ["app-container file mounts", "trstctl-agent secret-injection sidecar"],
      evidence_ref: "deploy/operator/crd.yaml",
    },
    modes: [
      {
        id: "file",
        name: "Shared-volume file injection",
        delivered_by: "trstctl-agent",
        workload_change: "pod template patch",
        secret_handling: "byte-backed",
        capabilities: ["no-code-workload-injection"],
      },
      {
        id: "env",
        name: "Environment reference injection",
        delivered_by: "Kubernetes valueFrom",
        workload_change: "env reference patch",
        secret_handling: "metadata-only",
        capabilities: ["env-reference"],
      },
    ],
    workload_kinds: ["Deployment", "StatefulSet", "DaemonSet"],
    sidecar_command: ["/usr/local/bin/trstctl-agent", "--secret-inject"],
    annotations: ["trstctl.com/secret-injection-hash"],
    sync_dependency: "TrstctlSecretSync",
    secret_handling: "operator reads source Secret metadata; sidecar copies bytes without string conversion",
    architecture_controls: ["AN-8"],
    evidence_refs: ["internal/operator/secretinjection.go", "internal/agent/secretinject/secretinject.go"],
    residuals: ["operator still uses a polling reconcile loop rather than a shared informer/workqueue controller"],
    recommended_next_actions: ["declare TrstctlSecretInjection items"],
  };
}

function unvaultedSecretPostureFixture() {
  return {
    capability: "CAP-SECR-07",
    served: true,
    generated_at: "2026-06-30T00:00:00Z",
    summary: {
      repository_sources: 1,
      third_party_sources: 1,
      cloud_secret_sources: 1,
      vault_providers_supported: 4,
      vault_providers_visible: 4,
      sync_targets_configured: 3,
      leaked_secret_findings: 1,
    },
    detection_sources: [
      {
        id: "repositories",
        name: "Git repository secret scanning",
        source_kind: "secret_repo",
        configured_count: 1,
        detection_mode: "served scan",
        secret_handling: "redacted metadata",
        findings_kind: "leaked_secret",
        capabilities: ["unvaulted-secret-detection"],
        evidence_refs: ["internal/secretscan/repository.go"],
      },
      {
        id: "third-party-artifacts",
        name: "CI/CD, registry, Slack, and Jira artifact scanning",
        source_kind: "secret_third_party",
        configured_count: 1,
        detection_mode: "served ingest",
        secret_handling: "redacted metadata",
        findings_kind: "leaked_secret",
        capabilities: ["unvaulted-secret-detection"],
        evidence_refs: ["internal/secretscan/thirdparty.go"],
      },
    ],
    vault_providers: [
      {
        id: "aws-secrets-manager",
        name: "AWS Secrets Manager",
        discovery_configured: true,
        discovery_source_count: 1,
        sync_supported: true,
        sync_configured: true,
        augmentation_mode: "sealed-outbox sync",
        capabilities: ["multi-vault-visibility"],
        evidence_refs: ["internal/discovery/cloudsecret/awssm/awssm.go"],
      },
      {
        id: "hashicorp-vault",
        name: "HashiCorp Vault KV",
        discovery_configured: true,
        discovery_source_count: 1,
        sync_supported: false,
        sync_configured: false,
        augmentation_mode: "metadata-only discovery",
        capabilities: ["multi-vault-visibility"],
        evidence_refs: ["internal/discovery/cloudsecret/vaultkv/vaultkv.go"],
      },
    ],
    configured_vaults: ["aws-secrets-manager", "gcp-secret-manager", "azure-key-vault", "hashicorp-vault"],
    configured_sync_targets: ["aws-secrets-manager", "gcp-secret-manager", "azure-key-vault"],
    workflow: ["detect", "augment"],
    secret_handling: "unvaulted detections persist metadata only and vault values never return through this route",
    architecture_controls: ["AN-8"],
    evidence_refs: ["internal/api/secrets.go"],
    residuals: ["automated pull-request rewrites remain outside this posture route"],
    recommended_next_actions: ["wire repository and third-party scan sources"],
  };
}

describe("secrets surface", () => {
  beforeEach(() => primeSecretsMocks());

  it("gives every secrets workspace one plain-language answer and one honest next action", async () => {
    const routes = [
      [
        "/secrets",
        "Secrets & Access",
        "See leaks, overdue rotation, failed delivery, ownership, and machine access before opening a secret value.",
        "Add secret",
      ],
      ["/secrets/access", "Machine access", "Which machine can use which secret, and why.", "Grant access"],
      [
        "/secrets/developer",
        "Use secrets in apps",
        "Choose one secret, review exactly how an app will read it, then test access without showing the value.",
        "Plan access",
      ],
      ["/secrets/sharing", "One-time secret links", "What can be viewed once, by whom, and until when.", "Create one-time link"],
      ["/secrets/engines", "Automatic secret sources", "Which systems can create short-lived credentials on demand.", "Add source"],
      ["/secrets/scanning", "Find leaked secrets in code", "Which repositories were checked and what needs removal.", "Connect repository"],
      ["/secrets/sync", "Send secrets to systems", "Where secrets are copied and whether each destination is current.", "Add destination"],
    ] as const;

    for (const [path, title, answer, action] of routes) {
      renderSecrets(path);
      expect(await screen.findByRole("heading", { name: title })).toBeInTheDocument();
      expect(screen.getByText(answer)).toBeInTheDocument();
      expect(within(screen.getByRole("group", { name: "Do next" })).getByRole("button", { name: action })).toBeInTheDocument();
      cleanup();
    }
  });

  it("opens with a served secrets risk cockpit instead of navigation-only KPI links", async () => {
    apiMock.secretRotationSchedules.mockResolvedValueOnce({
      items: [
        {
          id: "schedule-1",
          tenant_id: "t1",
          name: "payments-db",
          provider: "postgresql",
          key: "app/db/password",
          old_ref: "version:3",
          interval_seconds: 86400,
          enabled: true,
          next_run_at: new Date(Date.now() - 3_600_000).toISOString(),
          last_run_status: "delivery_failed",
          last_error: "destination did not confirm the new version",
          created_at: new Date().toISOString(),
          updated_at: new Date().toISOString(),
        },
      ],
    });
    renderSecrets();

    expect(await screen.findByRole("heading", { level: 1, name: "Secrets & Access" })).toBeInTheDocument();
    const health = await screen.findByRole("list", { name: "Secrets and access health" });
    expect(within(health).getByRole("link", { name: /1 leaked-secret finding/i })).toHaveAttribute("href", "/secrets/scanning");
    expect(within(health).getByRole("link", { name: /1 overdue rotation/i })).toHaveAttribute("href", "/secrets?focus=rotation");
    expect(within(health).getByRole("link", { name: /1 failed delivery/i })).toHaveAttribute("href", "/secrets/sync");
    expect(within(health).getByRole("link", { name: /0 secrets without an owner/i })).toHaveAttribute("href", "/secrets?owner=missing");

    const attention = screen.getByRole("list", { name: "Secrets and access attention" });
    expect(within(attention).getByText("payments-db")).toBeInTheDocument();
    expect(within(attention).getByText(/destination did not confirm/i)).toBeInTheDocument();
    expect(within(attention).getByRole("link", { name: "Repair delivery" })).toHaveAttribute("href", "/secrets/sync");
  });

  it("moves the three direct secrets jobs to their first safe field", async () => {
    const user = userEvent.setup();

    renderSecrets();
    await user.click(within(await screen.findByRole("group", { name: "Do next" })).getByRole("button", { name: "Add secret" }));
    expect(document.getElementById("secret-create-name")).toHaveFocus();

    cleanup();
    renderSecrets("/secrets/access");
    await user.click(within(await screen.findByRole("group", { name: "Do next" })).getByRole("button", { name: "Grant access" }));
    expect(screen.getByLabelText("Workload / subject")).toHaveFocus();

    cleanup();
    renderSecrets("/secrets/developer");
    await user.click(within(await screen.findByRole("group", { name: "Do next" })).getByRole("button", { name: "Plan access" }));
    expect(screen.getByLabelText("Secret name")).toHaveFocus();

    cleanup();
    renderSecrets("/secrets/sharing");
    await user.click(within(await screen.findByRole("group", { name: "Do next" })).getByRole("button", { name: "Create one-time link" }));
    expect(await screen.findByLabelText("Value to share")).toHaveFocus();
  });

  it("keeps advanced access closed and opens one secret-engine task at a time", async () => {
    const user = userEvent.setup();
    renderSecrets("/secrets/access");
    expect(await screen.findByRole("heading", { name: "Grant workload access" })).toBeInTheDocument();
    expect(screen.getByText("Machine login administration").closest("details")).not.toHaveAttribute("open");
    expect(screen.queryByRole("heading", { name: "Developer access" })).not.toBeInTheDocument();

    cleanup();
    renderSecrets("/secrets/developer");
    expect(await screen.findByRole("heading", { name: "Developer access" })).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Grant workload access" })).not.toBeInTheDocument();

    cleanup();
    renderSecrets("/secrets/engines");
    const chooser = (await screen.findByRole("heading", { name: "Choose what you want to do" })).closest("section") as HTMLElement;
    expect(screen.queryByRole("heading", { name: "Dynamic secrets" })).not.toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "PKI as a secret" })).not.toBeInTheDocument();
    await user.click(within(chooser).getByRole("button", { name: "Open temporary credential" }));
    expect(screen.getByRole("heading", { name: "Temporary backend credentials" })).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "PKI as a secret" })).not.toBeInTheDocument();
    await user.click(within(chooser).getByRole("button", { name: "Open certificate request" }));
    expect(screen.queryByRole("heading", { name: "Dynamic secrets" })).not.toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "PKI as a secret" })).toBeInTheDocument();
  });

  it("refuses to imply delivery when no secret destination is configured", async () => {
    const catalog = syncTargetCatalogFixture();
    apiMock.secretSyncTargets.mockResolvedValueOnce({
      ...catalog,
      configured_targets: [],
      targets: catalog.targets.map((target) => ({ ...target, configured: false })),
    });

    renderSecrets("/secrets/sync");

    expect(await screen.findByText("No destination is set up yet")).toBeInTheDocument();
    expect(screen.getByText(/will not accept a made-up target name/i)).toBeInTheDocument();
    expect(screen.queryByRole("form", { name: "Sync stored secret" })).not.toBeInTheDocument();
  });

  it("lists metadata, creates, reveals, rotates, and deletes native secrets without storage writes", async () => {
    const storageSpy = vi.spyOn(Storage.prototype, "setItem");
    const user = userEvent.setup();
    renderSecrets();

    expect(await screen.findByRole("heading", { name: "Secrets & Access" })).toBeInTheDocument();
    expect(await screen.findByRole("table", { name: "Native secret metadata" })).toBeInTheDocument();
    expect(screen.getByRole("searchbox", { name: "Search native secret metadata" })).toBeInTheDocument();
    expect(screen.getByText("app/db/password")).toBeInTheDocument();
    expect(screen.getByText("Payments platform")).toBeInTheDocument();
    expect(screen.getByText("production")).toBeInTheDocument();
    const metadataTable = screen.getByRole("table", { name: "Native secret metadata" });
    expect(within(metadataTable).getAllByRole("columnheader")).toHaveLength(5);
    expect(within(metadataTable).queryByRole("columnheader", { name: "Engine" })).not.toBeInTheDocument();
    expect(within(metadataTable).queryByRole("columnheader", { name: "Version" })).not.toBeInTheDocument();
    expect(within(metadataTable).queryByRole("columnheader", { name: "Created" })).not.toBeInTheDocument();
    expect(within(metadataTable).queryByText("native store")).not.toBeInTheDocument();
    expect(within(metadataTable).queryByText("v3")).not.toBeInTheDocument();
    expect(screen.getByRole("form", { name: "Run connector rotation" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Scheduled rotations" })).toBeInTheDocument();
    expect(screen.queryByText("Scheduled rotation and downstream sync aren't in the console yet")).not.toBeInTheDocument();
    expect(screen.getByText("Secret-change approvals")).toBeInTheDocument();
    expect(screen.getByText("No pending secret changes captured in this browser session.")).toBeInTheDocument();
    expect(screen.queryByText("Secret-change approvals aren't in the console yet")).not.toBeInTheDocument();
    expect(screen.queryByText("SUPER-SECRET")).not.toBeInTheDocument();

    // Machine-login administration is a served console surface now (C-S4):
    // methods + session ledger render, and no dead-end text remains.
    cleanup();
    renderSecrets("/secrets/access");
    expect(await screen.findByRole("heading", { name: "Auth methods" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Issued sessions" })).toBeInTheDocument();
    expect(screen.getByRole("group", { name: "Issued sessions" })).toHaveAttribute("tabindex", "0");
    expect(screen.getByText("Machine login administration").closest("details")).not.toHaveAttribute("open");
    expect(screen.queryByText(/isn't in the console yet/)).not.toBeInTheDocument();

    // Sync and platform-integration posture live on the Sync workspace tab.
    cleanup();
    renderSecrets("/secrets/sync");
    await waitFor(() => expect(apiMock.cloudSecretManagers).toHaveBeenCalled());
    expect(screen.getByText("CAP-SEC-04")).toBeInTheDocument();
    expect(screen.getByText("4 discovery providers, 3 sync targets configured")).toBeInTheDocument();
    expect(screen.getAllByText("HashiCorp Vault KV").length).toBeGreaterThan(0);
    expect(screen.getByText("not supported")).toBeInTheDocument();
    await waitFor(() => expect(apiMock.kubernetesSecretOperator).toHaveBeenCalled());
    expect(screen.getByText("CAP-SECR-04")).toBeInTheDocument();
    expect(screen.getByText("TrstctlSecretSync - served")).toBeInTheDocument();
    expect(screen.getAllByText("StatefulSet").length).toBeGreaterThan(0);
    await waitFor(() => expect(apiMock.secretWorkloadInjection).toHaveBeenCalled());
    expect(screen.getByText("CAP-SECR-05")).toBeInTheDocument();
    expect(screen.getByText("TrstctlSecretInjection - served")).toBeInTheDocument();
    expect(screen.getByText("Shared-volume file injection")).toBeInTheDocument();
    await waitFor(() => expect(apiMock.unvaultedSecrets).toHaveBeenCalled());
    expect(screen.getByText("CAP-SECR-07")).toBeInTheDocument();
    expect(screen.getByText("1 leaked findings, 4 vaults visible, 3 sync targets configured")).toBeInTheDocument();
    expect(screen.getByText("Git repository secret scanning: 1")).toBeInTheDocument();
    expect(screen.getAllByText("AWS Secrets Manager").length).toBeGreaterThan(0);

    cleanup();
    renderSecrets();
    await screen.findByText("app/db/password");
    await user.type(screen.getByRole("searchbox", { name: "Search native secret metadata" }), "cache");
    expect(screen.getByText("No secret metadata matches the current search.")).toBeInTheDocument();
    expect(screen.queryByText("app/db/password")).not.toBeInTheDocument();
    await user.clear(screen.getByRole("searchbox", { name: "Search native secret metadata" }));
    expect(screen.getByText("app/db/password")).toBeInTheDocument();

    const metadataRow = screen.getAllByRole("row", { name: /app\/db\/password/i })[0];
    expect(within(metadataRow).getAllByRole("button")).toHaveLength(3);
    expect(within(metadataRow).queryByRole("button", { name: /prepare rotate/i })).not.toBeInTheDocument();
    expect(within(metadataRow).queryByRole("button", { name: /prepare delete/i })).not.toBeInTheDocument();
    await user.click(within(metadataRow).getByRole("button", { name: /view metadata for app\/db\/password/i }));
    const drawer = screen.getByRole("dialog", { name: "Secret metadata" });
    expect(within(drawer).getByText("app/db/password")).toBeInTheDocument();
    expect(within(drawer).getByText("native store")).toBeInTheDocument();
    expect(within(drawer).getByText("v3")).toBeInTheDocument();
    expect(within(drawer).queryByText("SUPER-SECRET")).not.toBeInTheDocument();
    await user.click(within(drawer).getByRole("button", { name: /close/i }));

    expect(screen.queryByRole("form", { name: "Create secret" })).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Add secret" }));
    const createForm = within(screen.getByRole("form", { name: "Create secret" }));
    expect(createForm.getByLabelText("Secret name")).toHaveFocus();
    await user.type(createForm.getByLabelText("Secret name"), "app/cache/token");
    await user.type(createForm.getByLabelText("Secret value"), "new-secret-value");
    await user.selectOptions(createForm.getByLabelText("Owner"), "11111111-1111-4111-8111-111111111111");
    expect(createForm.queryByRole("button", { name: /create reviewed secret/i })).not.toBeInTheDocument();
    await user.click(createForm.getByRole("button", { name: /review exact plan/i }));

    await waitFor(() =>
      expect(apiMock.previewSecretCreate).toHaveBeenCalledWith({
        name: "app/cache/token",
        owner_id: "11111111-1111-4111-8111-111111111111",
        value: "new-secret-value",
      }),
    );
    const preview = await screen.findByRole("region", { name: "Native secret create review" });
    expect(within(preview).getByText("Exact create plan")).toBeInTheDocument();
    expect(within(preview).getByText(/preview made no writes/i)).toBeInTheDocument();
    expect(within(preview).getByText("Version 1", { selector: "dd" })).toBeInTheDocument();
    expect(within(preview).queryByText("new-secret-value")).not.toBeInTheDocument();
    expect(apiMock.createSecret).not.toHaveBeenCalled();

    await user.click(createForm.getByRole("button", { name: /previous/i }));
    await user.clear(createForm.getByLabelText("Secret value"));
    await user.type(createForm.getByLabelText("Secret value"), "changed-after-review");
    expect(createForm.getByText(/inputs changed after review/i)).toBeInTheDocument();
    expect(createForm.queryByRole("button", { name: /create reviewed secret/i })).not.toBeInTheDocument();
    await user.click(createForm.getByRole("button", { name: /review exact plan/i }));
    await waitFor(() => expect(apiMock.previewSecretCreate).toHaveBeenCalledTimes(2));

    await user.click(createForm.getByRole("button", { name: /create reviewed secret/i }));

    await waitFor(() =>
      expect(apiMock.createSecret).toHaveBeenCalledWith({
        name: "app/cache/token",
        owner_id: "11111111-1111-4111-8111-111111111111",
        value: "changed-after-review",
      }),
    );
    expect(await screen.findByText(/stored as version 1/i)).toBeInTheDocument();
    expect(screen.queryByText("new-secret-value")).not.toBeInTheDocument();
    expect(screen.queryByText("changed-after-review")).not.toBeInTheDocument();

    const row = screen.getAllByRole("row", { name: /app\/db\/password/i })[0];
    await user.click(within(row).getByRole("button", { name: /reveal value/i }));
    expect(await screen.findByText("SUPER-SECRET")).toBeInTheDocument();

    await user.click(within(row).getByRole("button", { name: /more actions for app\/db\/password/i }));
    await user.click(screen.getByRole("button", { name: /prepare rotate/i }));
    const rotateForm = within(screen.getByRole("form", { name: "Rotate secret" }));
    await user.type(rotateForm.getByLabelText("Replacement value"), "rotated-secret");
    await user.click(rotateForm.getByRole("button", { name: /rotate secret/i }));
    await waitFor(() =>
      expect(apiMock.rotateSecret).toHaveBeenCalledWith("app/db/password", {
        value: "rotated-secret",
      }),
    );
    expect(await screen.findByText(/rotated to version 4/i)).toBeInTheDocument();
    expect(screen.queryByText("rotated-secret")).not.toBeInTheDocument();

    const updatedRow = screen.getAllByRole("row", { name: /app\/db\/password/i })[0];
    await user.click(within(updatedRow).getByRole("button", { name: /more actions for app\/db\/password/i }));
    await user.click(screen.getByRole("button", { name: /prepare delete/i }));
    const deleteForm = within(screen.getByRole("form", { name: "Delete secret" }));
    await user.type(deleteForm.getByLabelText("Type the exact secret name"), "app/db/password");
    await user.click(deleteForm.getByRole("button", { name: /delete secret/i }));
    await waitFor(() => expect(apiMock.deleteSecret).toHaveBeenCalledWith("app/db/password"));
    expect(await screen.findByText(/deleted from the native store/i)).toBeInTheDocument();

    expect(storageSpy).not.toHaveBeenCalled();
    expect(localStorage.length).toBe(0);
    expect(sessionStorage.length).toBe(0);
  });

  it("keeps manual and scheduled rotation scope truthful and clears stale deferred evidence", async () => {
    const user = userEvent.setup();
    renderSecrets();
    await screen.findByText("app/db/password");

    const rotationForm = within(screen.getByRole("form", { name: "Run connector rotation" }));
    expect(rotationForm.queryByLabelText("TTL seconds")).not.toBeInTheDocument();
    await user.type(rotationForm.getByLabelText("Key"), "app/db/password");
    await user.type(rotationForm.getByLabelText("Old reference"), "version:3");
    await user.type(rotationForm.getByLabelText("Provider"), "dynamic-lease:postgresql");
    await user.click(rotationForm.getByRole("button", { name: /review rotation plan/i }));
    expect(await screen.findByText(/this provider does not yet have a durable worker-owned rotation path/i)).toBeInTheDocument();
    expect(apiMock.runSecretRotation).not.toHaveBeenCalled();

    await user.clear(rotationForm.getByLabelText("Provider"));
    await user.type(rotationForm.getByLabelText("Provider"), "postgresql");
    await user.click(rotationForm.getByRole("button", { name: /review rotation plan/i }));
    expect(await screen.findByText(/this provider does not yet have a durable worker-owned rotation path/i)).toBeInTheDocument();
    expect(apiMock.runSecretRotation).not.toHaveBeenCalled();

    await user.clear(rotationForm.getByLabelText("Provider"));
    await user.type(rotationForm.getByLabelText("Provider"), "connector:ci");
    await user.type(rotationForm.getByLabelText("Sync target (optional)"), "ci");
    await user.type(rotationForm.getByLabelText("Remote key (optional)"), "DATABASE_PASSWORD");
    await user.click(rotationForm.getByRole("button", { name: /review rotation plan/i }));
    await waitFor(() =>
      expect(apiMock.previewSecretRotation).toHaveBeenLastCalledWith({
        key: "app/db/password",
        old_ref: "version:3",
        provider: "connector:ci",
        target: "ci",
        remote_key: "DATABASE_PASSWORD",
      }),
    );
    expect(apiMock.runSecretRotation).not.toHaveBeenCalled();
    expect(await screen.findByText(/preview made no writes and contacted no external systems/i)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /run reviewed rotation/i }));
    await waitFor(() =>
      expect(apiMock.runSecretRotation).toHaveBeenCalledWith({
        key: "app/db/password",
        old_ref: "version:3",
        provider: "connector:ci",
        target: "ci",
        remote_key: "DATABASE_PASSWORD",
      }),
    );
    expect(await screen.findByText("Rotation queued for delivery")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: /new schedule/i }));
    const scheduleForm = within(screen.getByRole("form", { name: "Create rotation schedule" }));
    await user.type(scheduleForm.getByLabelText("Schedule name"), "daily-ci");
    await user.type(scheduleForm.getByLabelText("Key"), "app/db/password");
    await user.type(scheduleForm.getByLabelText("Old reference"), "version:3");
    await user.type(scheduleForm.getByLabelText("Provider"), "postgresql");
    await user.click(scheduleForm.getByRole("button", { name: /create schedule/i }));
    expect(await scheduleForm.findByText(/scheduled rotation currently requires a connector:<target> provider/i)).toBeInTheDocument();
    expect(apiMock.createSecretRotationSchedule).not.toHaveBeenCalled();

    await user.clear(scheduleForm.getByLabelText("Provider"));
    await user.type(scheduleForm.getByLabelText("Provider"), "connector:ci");
    await user.click(scheduleForm.getByRole("button", { name: /create schedule/i }));
    await waitFor(() =>
      expect(apiMock.createSecretRotationSchedule).toHaveBeenCalledWith({
        name: "daily-ci",
        key: "app/db/password",
        old_ref: "version:3",
        provider: "connector:ci",
        interval_seconds: 86400,
        enabled: true,
      }),
    );

    await user.click(screen.getByRole("button", { name: "Run due now" }));
    await waitFor(() => expect(apiMock.runDueSecretRotations).toHaveBeenCalledTimes(1));
    expect(await screen.findByText("Ran 50 due rotations; deferred 1 of 51 scanned schedules.")).toBeInTheDocument();
    expect(screen.getByText(/full 50-run budget was consumed/i)).toBeInTheDocument();
    expect(screen.queryByText(/full 500-schedule scan budget was consumed/i)).not.toBeInTheDocument();
    expect(screen.getByText(/1 due schedules remain deferred; each exact due edge is listed below/i)).toBeInTheDocument();
    const deferredList = screen.getByRole("list", { name: "Deferred rotation schedule evidence" });
    const deferredRow = within(deferredList).getByRole("listitem");
    expect(within(deferredRow).getByText("77777777-7777-7777-7777-777777777777")).toBeInTheDocument();
    expect(within(deferredRow).getByText("Approval pending")).toBeInTheDocument();
    expect(within(deferredRow).getByText("Due Jun 19, 2026, 10:00 AM")).toBeInTheDocument();
    expect(within(deferredRow).getByText("scheduled rotation is waiting for approval")).toBeInTheDocument();

    apiMock.runDueSecretRotations.mockRejectedValueOnce(
      new ApiError(
        503,
        JSON.stringify({
          ran: 1,
          scanned: 500,
          runs: [scheduledRunFixture(0)],
          deferred: [
            {
              schedule_id: "99999999-9999-4999-8999-999999999999",
              reason: "command_claimed",
              due_at: "2026-06-19T10:02:00Z",
              error: "scheduled rotation command is already in progress",
            },
          ],
          run_limit_reached: false,
          scan_limit_reached: true,
          complete: false,
          partial: true,
          failed_schedule_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
          system_error: "scheduler processing failed; retry this tick and inspect server logs",
        }),
      ),
    );
    await user.click(screen.getByRole("button", { name: "Run due now" }));
    await waitFor(() => expect(apiMock.runDueSecretRotations).toHaveBeenCalledTimes(2));
    expect(await screen.findByText("scheduler processing failed; retry this tick and inspect server logs")).toBeInTheDocument();
    expect(screen.getByText("app/partial/password")).toBeInTheDocument();
    const partialDeferredList = screen.getByRole("list", { name: "Deferred rotation schedule evidence" });
    expect(within(partialDeferredList).getByText("99999999-9999-4999-8999-999999999999")).toBeInTheDocument();
    expect(within(partialDeferredList).getByText("Due edge claimed by another runner")).toBeInTheDocument();
    expect(within(partialDeferredList).getByText("scheduled rotation command is already in progress")).toBeInTheDocument();
    expect(screen.getByText(/full 500-schedule scan budget was consumed/i)).toBeInTheDocument();
    expect(screen.queryByText(/full 50-run budget was consumed/i)).not.toBeInTheDocument();
    expect(screen.queryByText("77777777-7777-7777-7777-777777777777")).not.toBeInTheDocument();

    apiMock.runDueSecretRotations.mockRejectedValueOnce(
      new ApiError(
        503,
        JSON.stringify({
          detail: "malformed scheduler receipt",
          ran: 0,
          scanned: 2,
          runs: [],
          deferred: [
            {
              schedule_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
              reason: "constructor",
              due_at: "2026-06-19T10:03:00Z",
            },
            {
              schedule_id: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
              reason: "toString",
              due_at: "2026-06-19T10:04:00Z",
            },
          ],
          run_limit_reached: false,
          scan_limit_reached: false,
          complete: false,
          partial: true,
          system_error: "must not render inherited prototype keys as a deferred reason",
        }),
      ),
    );
    await user.click(screen.getByRole("button", { name: "Run due now" }));
    expect(await screen.findByText("Could not run due rotations")).toBeInTheDocument();
    await waitFor(() => expect(apiMock.runDueSecretRotations).toHaveBeenCalledTimes(3));
    expect(screen.queryByRole("list", { name: "Deferred rotation schedule evidence" })).not.toBeInTheDocument();
    expect(screen.queryByText("77777777-7777-7777-7777-777777777777")).not.toBeInTheDocument();
    expect(screen.queryByText("Approval pending")).not.toBeInTheDocument();
    expect(screen.queryByText("99999999-9999-4999-8999-999999999999")).not.toBeInTheDocument();
    expect(screen.queryByText("app/partial/password")).not.toBeInTheDocument();
    expect(screen.queryByRole("status", { name: "Scheduled rotation continuation notice" })).not.toBeInTheDocument();

    const maliciousSchedulerError = "credential=super-secret subject=alice@example.test remote=vault/alice";
    apiMock.runDueSecretRotations.mockRejectedValueOnce(
      new ApiError(
        503,
        JSON.stringify({
          ran: 0,
          scanned: 0,
          runs: [],
          deferred: [],
          run_limit_reached: false,
          scan_limit_reached: false,
          complete: false,
          partial: false,
          system_error: maliciousSchedulerError,
        }),
      ),
    );
    await user.click(screen.getByRole("button", { name: "Run due now" }));
    await waitFor(() => expect(apiMock.runDueSecretRotations).toHaveBeenCalledTimes(4));
    expect(await screen.findByText("Could not run due rotations")).toBeInTheDocument();
    expect(screen.queryByText(maliciousSchedulerError)).not.toBeInTheDocument();
  });

  it("queues denied secret changes for distinct approval and retry completion", async () => {
    const user = userEvent.setup();
    apiMock.rotateSecret
      .mockRejectedValueOnce(
        new ApiError(403, JSON.stringify({ detail: "dual control: this action has not been approved by the required number of distinct approvers" })),
      )
      .mockResolvedValueOnce({ name: "app/db/password", version: 4, updated_at: "2026-06-19T11:00:00Z" });
    apiMock.deleteSecret
      .mockRejectedValueOnce(
        new ApiError(403, JSON.stringify({ detail: "dual control: this action has not been approved by the required number of distinct approvers" })),
      )
      .mockResolvedValueOnce(undefined);
    apiMock.approveSecretChange
      .mockResolvedValueOnce({ resource: "secret:app/db/password", action: "rotate", approver: "bob", approvals: 2 })
      .mockResolvedValueOnce({ resource: "secret:app/db/password", action: "delete", approver: "carol", approvals: 2 });
    apiMock.approvalRequests.mockResolvedValue([
      {
        id: "019fec49-6641-7131-ae7f-17f7ea4b5e01",
        intent_digest: "sha256:secret-rotate",
        resource_id: "secret:app/db/password",
        resource_name: "app/db/password",
        resource_kind: "secret",
        action: "rotate",
        requester: "alice",
        target_version: "secret:3",
        evidence_refs: [],
        approval_count: 1,
        required_approvals: 2,
        status: "pending",
        created_at: "2026-06-19T10:00:00Z",
        expires_at: "2026-06-19T11:00:00Z",
      },
      {
        id: "019fec49-6641-7131-ae7f-17f7ea4b5e02",
        intent_digest: "sha256:secret-delete",
        resource_id: "secret:app/db/password",
        resource_name: "app/db/password",
        resource_kind: "secret",
        action: "delete",
        requester: "alice",
        target_version: "secret:3",
        evidence_refs: [],
        approval_count: 1,
        required_approvals: 2,
        status: "pending",
        created_at: "2026-06-19T10:00:00Z",
        expires_at: "2026-06-19T11:00:00Z",
      },
    ]);

    renderSecrets();
    await screen.findByText("app/db/password");

    const deniedRotateRow = screen.getAllByRole("row", { name: /app\/db\/password/i })[0];
    await user.click(within(deniedRotateRow).getByRole("button", { name: /more actions for app\/db\/password/i }));
    await user.click(screen.getByRole("button", { name: /prepare rotate/i }));
    const rotateForm = within(screen.getByRole("form", { name: "Rotate secret" }));
    await user.type(rotateForm.getByLabelText("Replacement value"), "approval-rotate-value");
    await user.click(rotateForm.getByRole("button", { name: /rotate secret/i }));

    await waitFor(() =>
      expect(apiMock.rotateSecret).toHaveBeenNthCalledWith(1, "app/db/password", {
        value: "approval-rotate-value",
      }),
    );
    expect(await screen.findByText("Rotation is waiting for secret-change approval.")).toBeInTheDocument();
    expect(screen.getByText("Rotate/update - app/db/password")).toBeInTheDocument();

    let approvalList = screen.getByRole("list", { name: "Pending secret-change approvals" });
    await user.click(within(approvalList).getByRole("button", { name: /approve rotate\/update for app\/db\/password/i }));
    await waitFor(() =>
      expect(apiMock.approveSecretChange).toHaveBeenNthCalledWith(1, "app/db/password", {
        action: "rotate",
        request_id: "019fec49-6641-7131-ae7f-17f7ea4b5e01",
        intent_digest: "sha256:secret-rotate",
      }),
    );
    expect(await screen.findByText(/bob approved Rotate\/update for app\/db\/password/i)).toBeInTheDocument();

    approvalList = screen.getByRole("list", { name: "Pending secret-change approvals" });
    await user.click(within(approvalList).getByRole("button", { name: /retry rotate\/update for app\/db\/password/i }));
    await waitFor(() => expect(apiMock.rotateSecret).toHaveBeenCalledTimes(2));
    expect(apiMock.rotateSecret).toHaveBeenLastCalledWith("app/db/password", {
      value: "approval-rotate-value",
    });
    expect(await screen.findByText(/rotated to version 4 after approval/i)).toBeInTheDocument();
    expect(screen.queryByDisplayValue("approval-rotate-value")).not.toBeInTheDocument();

    const deniedDeleteRow = screen.getAllByRole("row", { name: /app\/db\/password/i })[0];
    await user.click(within(deniedDeleteRow).getByRole("button", { name: /more actions for app\/db\/password/i }));
    await user.click(screen.getByRole("button", { name: /prepare delete/i }));
    const deleteForm = within(screen.getByRole("form", { name: "Delete secret" }));
    await user.type(deleteForm.getByLabelText("Type the exact secret name"), "app/db/password");
    await user.click(deleteForm.getByRole("button", { name: /delete secret/i }));

    await waitFor(() => expect(apiMock.deleteSecret).toHaveBeenNthCalledWith(1, "app/db/password"));
    expect(await screen.findByText("Delete is waiting for secret-change approval.")).toBeInTheDocument();
    expect(screen.getByText("Delete - app/db/password")).toBeInTheDocument();

    approvalList = screen.getByRole("list", { name: "Pending secret-change approvals" });
    await user.click(within(approvalList).getByRole("button", { name: /approve delete for app\/db\/password/i }));
    await waitFor(() =>
      expect(apiMock.approveSecretChange).toHaveBeenNthCalledWith(2, "app/db/password", {
        action: "delete",
        request_id: "019fec49-6641-7131-ae7f-17f7ea4b5e02",
        intent_digest: "sha256:secret-delete",
      }),
    );
    expect(await screen.findByText(/carol approved Delete for app\/db\/password/i)).toBeInTheDocument();

    approvalList = screen.getByRole("list", { name: "Pending secret-change approvals" });
    await user.click(within(approvalList).getByRole("button", { name: /retry delete for app\/db\/password/i }));
    await waitFor(() => expect(apiMock.deleteSecret).toHaveBeenCalledTimes(2));
    expect(apiMock.deleteSecret).toHaveBeenLastCalledWith("app/db/password");
    expect(await screen.findByText(/deleted after approval/i)).toBeInTheDocument();
  });

  it("reviews, executes, retries, and verifies the exact developer access plan without rendering the value", async () => {
    const storageSpy = vi.spyOn(Storage.prototype, "setItem");
    const user = userEvent.setup();
    renderSecrets("/secrets/developer");

    const reviewForm = within(await screen.findByRole("form", { name: "Review developer secret access" }));
    expect(screen.queryByText(/trstctl run --secret/)).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Import unavailable" })).toBeDisabled();
    expect(screen.queryByText("SUPER-SECRET")).not.toBeInTheDocument();

    await user.click(reviewForm.getByRole("button", { name: "Review access plan" }));
    await waitFor(() =>
      expect(apiMock.previewSecretAccess).toHaveBeenCalledWith({
        name: "app/db/password",
        env_var: "DB_PASSWORD",
        resolve: false,
      }),
    );
    expect(await screen.findByText("Ready to test")).toBeInTheDocument();
    expect(screen.getByText("trstctl run --secret DB_PASSWORD=app/db/password -- ./service")).toBeInTheDocument();
    expect(screen.getByText(/client\.secrets\.get\("app\/db\/password", \{ resolve: false \}\)/)).toBeInTheDocument();
    expect(screen.getByText("secrets:read")).toBeInTheDocument();
    expect(screen.getByText(/preview made no writes and no external calls/i)).toBeInTheDocument();

    apiMock.getSecret.mockRejectedValueOnce(new Error("tenant key domain is temporarily sealed"));
    await user.click(screen.getByRole("button", { name: "Run reviewed access test" }));
    expect(await screen.findByText(/tenant key domain is temporarily sealed/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Retry reviewed access test" })).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Retry reviewed access test" }));

    await waitFor(() => expect(apiMock.getSecret).toHaveBeenLastCalledWith("app/db/password", { resolve: false }));
    expect(await screen.findByText(/Verified app\/db\/password version 3/i)).toBeInTheDocument();
    expect(screen.getByText(/matched the reviewed plan/i)).toBeInTheDocument();
    expect(screen.queryByText("SUPER-SECRET")).not.toBeInTheDocument();
    expect(storageSpy.mock.calls.some((call) => JSON.stringify(call).includes("SUPER-SECRET"))).toBe(false);

    await user.clear(reviewForm.getByLabelText("Environment variable"));
    await user.type(reviewForm.getByLabelText("Environment variable"), "DATABASE_PASSWORD");
    expect(screen.getByText(/configuration changed after review/i)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Run reviewed access test" })).not.toBeInTheDocument();
  });

  it("issues ephemeral API keys, runs secret scans, and drives leases", async () => {
    const storageSpy = vi.spyOn(Storage.prototype, "setItem");
    const user = userEvent.setup();
    renderSecrets("/secrets/sharing");

    await user.click(await screen.findByRole("button", { name: "Open temporary access" }));
    expect(await screen.findByRole("heading", { name: "Ephemeral API keys" })).toBeInTheDocument();
    expect(screen.getByText("What happens")).toBeInTheDocument();
    expect(screen.getByText(/narrowly scoped key/i)).toBeInTheDocument();
    const issueForm = within(screen.getByRole("form", { name: "Review ephemeral API key" }));
    await user.type(issueForm.getByLabelText("Machine subject"), "ci/deploy-preview");
    await user.click(issueForm.getByRole("button", { name: "Review temporary key" }));

    await waitFor(() =>
      expect(apiMock.previewEphemeralAPIKey).toHaveBeenCalledWith({
        subject: "ci/deploy-preview",
        scopes: ["access:read"],
        ttl_seconds: 900,
      }),
    );
    expect(apiMock.issueEphemeralAPIKey).not.toHaveBeenCalled();
    await user.click(await screen.findByRole("button", { name: "Issue reviewed key" }));

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
    await user.click(screen.getByRole("button", { name: /dismiss/i }));
    expect(screen.queryByText("epk_live_reveal_once_123")).not.toBeInTheDocument();

    cleanup();
    renderSecrets("/secrets/scanning");
    expect(await screen.findByRole("heading", { name: "Code and CI secret scanning bridge" })).toBeInTheDocument();
    await waitFor(() => expect(apiMock.secretRepositoryScanning).toHaveBeenCalled());
    await waitFor(() => expect(apiMock.thirdPartySecretScanning).toHaveBeenCalled());
    expect(screen.getByText("CAP-SCAN-01")).toBeInTheDocument();
    expect(screen.getByText("CAP-SCAN-04")).toBeInTheDocument();
    expect(screen.getByText("GitHub")).toBeInTheDocument();
    expect(screen.getByText("GitLab")).toBeInTheDocument();
    expect(screen.getByText("Bitbucket")).toBeInTheDocument();
    expect(screen.getAllByText("Slack").length).toBeGreaterThan(0);
    expect(screen.getByText("/api/v1/secrets/scans/third-party/slack/ingest")).toBeInTheDocument();
    expect(screen.getByText("/api/v1/secrets/scans/repositories/github/webhook")).toBeInTheDocument();
    const thirdPartyForm = within(screen.getByRole("form", { name: "Queue third-party secret scan" }));
    await user.selectOptions(thirdPartyForm.getByLabelText("External source"), "slack");
    await user.type(thirdPartyForm.getByLabelText("Source ref"), "acme/slack");
    await user.type(thirdPartyForm.getByLabelText("Artifact path"), "/var/lib/trstctl/exports/slack.jsonl");
    await user.type(thirdPartyForm.getByLabelText("Event"), "message_export");
    await user.click(thirdPartyForm.getByRole("button", { name: /queue scan/i }));
    await waitFor(() =>
      expect(apiMock.ingestThirdPartySecretScan).toHaveBeenCalledWith("slack", {
        source: "acme/slack",
        artifact_path: "/var/lib/trstctl/exports/slack.jsonl",
        event: "message_export",
      }),
    );
    expect(await screen.findByText(/slack scan queued as run 66666666-6666-6666-6666-666666666666/i)).toBeInTheDocument();
    const scanForm = within(screen.getByRole("form", { name: "Run secret scan" }));
    await user.type(scanForm.getByLabelText("Path"), "github.com/example/payments");
    await user.click(scanForm.getByRole("button", { name: /review scan/i }));
    await waitFor(() => expect(apiMock.previewSecretScan).toHaveBeenCalledWith({ path: "github.com/example/payments", mode: "workspace" }));
    expect(apiMock.scanSecrets).not.toHaveBeenCalled();
    await user.click(await screen.findByRole("button", { name: "Run reviewed scan" }));
    await waitFor(() =>
      expect(apiMock.scanSecrets).toHaveBeenCalledWith(
        { path: "github.com/example/payments", mode: "workspace", preview_fingerprint: "sha256:reviewed-f39" },
        expect.any(String),
      ),
    );
    expect(await screen.findByText("55555555-5555-5555-5555-555555555555")).toBeInTheDocument();
    expect(screen.getByText("entropy-rules")).toBeInTheDocument();
    expect(screen.getByText("generic-api-key")).toBeInTheDocument();
    expect(screen.getByText("config/ci.yml")).toBeInTheDocument();
    expect(screen.getByText("sha256:6e5a...91bb")).toBeInTheDocument();

    cleanup();
    renderSecrets("/secrets/engines");
    await user.click(await screen.findByRole("button", { name: "Open temporary credential" }));
    expect(await screen.findByRole("heading", { name: "Temporary backend credentials" })).toBeInTheDocument();
    await user.selectOptions(screen.getByLabelText("Connected provider"), "payments-db");
    await user.clear(screen.getByLabelText("Lifetime in seconds"));
    await user.type(screen.getByLabelText("Lifetime in seconds"), "1200");
    await user.click(screen.getByRole("button", { name: "Review without creating" }));
    await waitFor(() => expect(apiMock.previewDynamicLease).toHaveBeenCalledWith({ provider: "payments-db", role: "readonly-reporting", ttl_seconds: 1200 }));
    expect(apiMock.issueDynamicLease).not.toHaveBeenCalled();
    await user.click(await screen.findByRole("button", { name: "Create reviewed credential" }));
    await waitFor(() =>
      expect(apiMock.issueDynamicLease).toHaveBeenCalledWith(
        { provider: "payments-db", role: "readonly-reporting", ttl_seconds: 1200, preview_fingerprint: "sha256:reviewed-f65" },
        expect.any(String),
      ),
    );
    expect(await screen.findByText("lease-postgres-1")).toBeInTheDocument();
    expect(screen.getByText("postgres://lease-secret")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /dismiss/i }));
    expect(screen.queryByText("postgres://lease-secret")).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /renew lease/i }));
    await waitFor(() => expect(apiMock.renewDynamicLease).toHaveBeenCalledWith("lease-postgres-1", { extend_seconds: 300 }));
    await user.click(screen.getByRole("button", { name: /revoke lease/i }));
    await waitFor(() => expect(apiMock.revokeDynamicLease).toHaveBeenCalledWith("lease-postgres-1"));
    expect(await screen.findByRole("heading", { name: "Lease revoked; prove the login is dead" })).toBeInTheDocument();
    expect(screen.getByText("State")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /mint key|triage leak|rotate leaked/i })).not.toBeInTheDocument();
    expect(storageSpy).not.toHaveBeenCalled();
    expect(localStorage.length).toBe(0);
    expect(sessionStorage.length).toBe(0);
  });

  it("keeps the failed F39 run visible and retries the exact reviewed request with one idempotency key", async () => {
    const user = userEvent.setup();
    apiMock.scanSecrets.mockRejectedValueOnce(new Error("temporary scanner failure"));
    renderSecrets("/secrets/scanning");

    const form = within(await screen.findByRole("form", { name: "Run secret scan" }));
    await user.type(form.getByLabelText("Path"), "github.com/example/payments");
    await user.click(form.getByRole("button", { name: "Review scan" }));
    await user.click(await screen.findByRole("button", { name: "Run reviewed scan" }));

    expect(await screen.findByText(/temporary scanner failure/i)).toBeInTheDocument();
    const firstKey = apiMock.scanSecrets.mock.calls[0]?.[1];
    expect(firstKey).toEqual(expect.any(String));
    await user.click(screen.getByRole("button", { name: "Retry reviewed scan" }));
    await waitFor(() => expect(apiMock.scanSecrets).toHaveBeenCalledTimes(2));
    expect(apiMock.scanSecrets.mock.calls[1]?.[1]).toBe(firstKey);
    expect(await screen.findByText("55555555-5555-5555-5555-555555555555")).toBeInTheDocument();
  });

  it("runs transit encrypt/decrypt and keeps secret sync disclosure scoped", async () => {
    const storageSpy = vi.spyOn(Storage.prototype, "setItem");
    const user = userEvent.setup();
    renderSecrets("/secrets/engines");

    await user.click(await screen.findByRole("button", { name: "Open encryption and signing" }));
    expect(await screen.findByRole("heading", { name: "Transit and KMIP" })).toBeInTheDocument();
    expect(await screen.findByText("Sealed restore ready")).toBeInTheDocument();
    expect(screen.getByText("KMIP not configured")).toBeInTheDocument();
    expect(await screen.findByText("transit.key.rotated")).toBeInTheDocument();

    const keyForm = within(screen.getByRole("form", { name: "Create a Transit key" }));
    await user.type(keyForm.getByLabelText("Key name"), "payments-pii");
    await user.selectOptions(keyForm.getByLabelText("Key purpose"), "aead");
    await user.click(keyForm.getByRole("button", { name: "Create key" }));
    await waitFor(() => expect(apiMock.createTransitKey).toHaveBeenCalledWith({ name: "payments-pii", kind: "aead" }));

    await user.type(keyForm.getByLabelText("Key name"), "payments-integrity");
    await user.selectOptions(keyForm.getByLabelText("Key purpose"), "hmac");
    await user.click(keyForm.getByRole("button", { name: "Create key" }));
    await waitFor(() => expect(apiMock.createTransitKey).toHaveBeenCalledWith({ name: "payments-integrity", kind: "hmac" }));

    await user.type(keyForm.getByLabelText("Key name"), "payments-signing");
    await user.selectOptions(keyForm.getByLabelText("Key purpose"), "sign");
    await user.click(keyForm.getByRole("button", { name: "Create key" }));
    await waitFor(() => expect(apiMock.createTransitKey).toHaveBeenCalledWith({ name: "payments-signing", kind: "sign" }));

    const transitForm = within(screen.getByRole("form", { name: "Transit encrypt and decrypt" }));
    expect(transitForm.getByLabelText("Encryption key")).toHaveValue("payments-pii");
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
    expect(screen.getAllByText("trst:v1:ciphertext").length).toBeGreaterThan(0);
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

    await user.click(screen.getByRole("button", { name: "Rotate payments-pii" }));
    await waitFor(() => expect(apiMock.rotateTransitKey).toHaveBeenCalledWith({ name: "payments-pii" }));
    expect(await screen.findByText("Version 2")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Rotate payments-integrity" }));
    await waitFor(() => expect(apiMock.rotateTransitKey).toHaveBeenCalledWith({ name: "payments-integrity" }));
    await user.click(screen.getByRole("button", { name: "Rotate payments-signing" }));
    await waitFor(() => expect(apiMock.rotateTransitKey).toHaveBeenCalledWith({ name: "payments-signing" }));
    await user.type(screen.getByLabelText("Message"), "receipt body");
    await user.click(screen.getByRole("button", { name: /compute hmac/i }));
    await waitFor(() =>
      expect(apiMock.hmacTransit).toHaveBeenCalledWith({
        key: "payments-integrity",
        data: "cmVjZWlwdCBib2R5",
      }),
    );
    await user.click(screen.getByRole("button", { name: /sign message/i }));
    await waitFor(() =>
      expect(apiMock.signTransit).toHaveBeenCalledWith({
        key: "payments-signing",
        message: "cmVjZWlwdCBib2R5",
      }),
    );
    expect(await screen.findByDisplayValue("signature-base64")).toBeInTheDocument();
    expect(screen.getByDisplayValue("public-der-base64")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Verify signature" }));
    await waitFor(() =>
      expect(apiMock.verifyTransit).toHaveBeenCalledWith({
        message: "cmVjZWlwdCBib2R5",
        signature: "signature-base64",
        public_der: "public-der-base64",
      }),
    );
    expect(await screen.findByText("Valid signature")).toBeInTheDocument();
    expect(await screen.findByText("Version 2 (current)")).toBeInTheDocument();

    cleanup();
    renderSecrets("/secrets/sync");
    expect(await screen.findByRole("heading", { name: "Secret sync and platform integrations" })).toBeInTheDocument();
    const syncForm = within(screen.getByRole("form", { name: "Sync stored secret" }));
    expect(syncForm.getByLabelText("Secret name")).toHaveValue("app/db/password");
    await user.type(syncForm.getByLabelText("Target"), "kubernetes/prod");
    await user.type(syncForm.getByLabelText("Remote key"), "Secret/payments-db/password");
    await user.click(syncForm.getByRole("button", { name: /sync secret/i }));
    await waitFor(() =>
      expect(apiMock.syncSecret).toHaveBeenCalledWith({
        name: "app/db/password",
        target: "kubernetes/prod",
        remote_key: "Secret/payments-db/password",
      }),
    );
    expect(await screen.findByText("Queued")).toBeInTheDocument();
    expect(screen.getByText("Not delivered")).toBeInTheDocument();
    expect(screen.getByText("Secret/payments-db/password")).toBeInTheDocument();
    expect(screen.queryByText(/raw target token|BEGIN .* PRIVATE KEY/)).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /push|rollback/i })).not.toBeInTheDocument();
    expect(storageSpy).not.toHaveBeenCalled();
    expect(localStorage.length).toBe(0);
    expect(sessionStorage.length).toBe(0);
  });

  it("turns an uncertain Transit operation into an explicit proof-first recovery journey", async () => {
    apiMock.transitKeys.mockResolvedValue({ items: [{ name: "payments-signing", kind: "sign", version: 2 }] });
    apiMock.signTransit.mockRejectedValueOnce(new Error("the response ended before the outcome was confirmed"));
    const user = userEvent.setup();
    renderSecrets("/secrets/engines");

    await user.click(await screen.findByRole("button", { name: "Open encryption and signing" }));
    await user.type(await screen.findByLabelText("Message"), "receipt body");
    await user.click(screen.getByRole("button", { name: "Sign message" }));

    expect(await screen.findByText("Transit operation failed")).toBeInTheDocument();
    expect(screen.getByText(/Refresh server status, version history, and audit evidence before retrying/)).toBeInTheDocument();
    expect(apiMock.signTransit).toHaveBeenCalledTimes(1);

    const postureCalls = apiMock.transitPosture.mock.calls.length;
    const versionCalls = apiMock.transitKeyVersions.mock.calls.length;
    const auditCalls = apiMock.auditEvents.mock.calls.length;
    await user.click(screen.getByRole("button", { name: "Refresh recovery proof" }));
    await waitFor(() => {
      expect(apiMock.transitPosture.mock.calls.length).toBeGreaterThan(postureCalls);
      expect(apiMock.transitKeyVersions.mock.calls.length).toBeGreaterThan(versionCalls);
      expect(apiMock.auditEvents.mock.calls.length).toBeGreaterThan(auditCalls);
    });
    expect(apiMock.signTransit).toHaveBeenCalledTimes(1);
  });

  it("issues PKI secrets, tests machine login, and creates/redeems one-time shares once", async () => {
    const storageSpy = vi.spyOn(Storage.prototype, "setItem");
    apiMock.previewPKISecret.mockResolvedValueOnce({
      capability: "F67",
      operation: "issue_certificate",
      ready: true,
      effect_free: true,
      custody_mode: "requester_csr",
      common_name: "svc.internal",
      dns_names: ["svc.internal", "api.svc.internal"],
      requested_ttl_seconds: 600,
      effective_ttl_seconds: 600,
      profile: "secrets-api",
      ca_certificate_sha256: "sha256:ca",
      csr_sha256: "sha256:csr",
      subject_key_algorithm: "ECDSA",
      subject_key_bits: 256,
      required_permission: "secrets:write",
      request_fingerprint: "sha256:reviewed-csr",
      vault_path: "/v1/pki/sign/default",
      prerequisites: [{ id: "issuing_ca", ready: true, detail: "Issuing CA connected." }],
      blockers: [],
      preview_writes: [],
      preview_external_effects: [],
      execute_writes: ["record the issued serial"],
      execute_external_effects: ["ask the signer to sign one certificate"],
      recovery_steps: ["revoke the exact issued serial"],
      verification_steps: ["verify the returned certificate"],
      cli_argv: ["trstctl", "secrets", "pki", "-f", "pki-request.json"],
      secret_data_handling: "The private key stays with the requester.",
    });
    apiMock.issuePKISecret.mockResolvedValueOnce({
      serial: "pki-csr-01",
      common_name: "svc.internal",
      certificate: "-----BEGIN CERTIFICATE-----\nCSR-CERT\n-----END CERTIFICATE-----",
    });
    apiMock.redeemShare
      .mockResolvedValueOnce({ value: "redeemed-secret" })
      .mockRejectedValueOnce(new ApiError(410, JSON.stringify({ detail: "share already redeemed" })));
    const user = userEvent.setup();
    renderSecrets("/secrets/engines");

    await user.click(await screen.findByRole("button", { name: "Open certificate request" }));
    const pkiForm = within(await screen.findByRole("form", { name: "Issue PKI secret" }));
    expect(pkiForm.getByLabelText("Key custody")).toHaveValue("csr");
    await user.type(
      pkiForm.getByLabelText("Certificate signing request (PKCS#10)"),
      "-----BEGIN CERTIFICATE REQUEST-----\nCSR\n-----END CERTIFICATE REQUEST-----",
    );
    await user.clear(pkiForm.getByLabelText("TTL seconds"));
    await user.type(pkiForm.getByLabelText("TTL seconds"), "600");
    await user.click(pkiForm.getByRole("button", { name: /review without issuing/i }));

    await waitFor(() =>
      expect(apiMock.previewPKISecret).toHaveBeenCalledWith({
        csr_pem: "-----BEGIN CERTIFICATE REQUEST-----\nCSR\n-----END CERTIFICATE REQUEST-----",
        ttl_seconds: 600,
      }),
    );
    expect(await pkiForm.findByText("Ready to issue")).toBeInTheDocument();
    expect(pkiForm.getByText("Issuing CA connected.")).toBeInTheDocument();
    expect(pkiForm.getByText("svc.internal, api.svc.internal")).toBeInTheDocument();
    expect(apiMock.issuePKISecret).not.toHaveBeenCalled();
    await user.click(pkiForm.getByRole("button", { name: /issue reviewed certificate/i }));

    await waitFor(() =>
      expect(apiMock.issuePKISecret).toHaveBeenCalledWith({
        csr_pem: "-----BEGIN CERTIFICATE REQUEST-----\nCSR\n-----END CERTIFICATE REQUEST-----",
        ttl_seconds: 600,
        preview_fingerprint: "sha256:reviewed-csr",
      }),
    );
    expect(await screen.findByText(/PKI bundle pki-csr-01/i)).toBeInTheDocument();
    expect(screen.getByText(/Its private key remains where you generated the CSR/i)).toBeInTheDocument();
    expect(screen.queryByText(/BEGIN PRIVATE KEY/)).not.toBeInTheDocument();

    cleanup();
    renderSecrets("/secrets/engines");
    await user.click(await screen.findByRole("button", { name: "Open certificate request" }));
    const legacyForm = within(await screen.findByRole("form", { name: "Issue PKI secret" }));
    apiMock.previewPKISecret.mockResolvedValueOnce({
      capability: "F67",
      operation: "issue_certificate",
      ready: true,
      effect_free: true,
      custody_mode: "deprecated_server_keygen",
      common_name: "legacy.internal",
      dns_names: [],
      requested_ttl_seconds: 900,
      effective_ttl_seconds: 900,
      profile: "secrets-api",
      ca_certificate_sha256: "sha256:ca",
      subject_key_algorithm: "ECDSA",
      subject_key_bits: 256,
      required_permission: "secrets:write",
      request_fingerprint: "sha256:reviewed-legacy",
      vault_path: "/v1/pki/issue/default",
      prerequisites: [{ id: "durable_deprecation_evidence", ready: true, detail: "Audit evidence is available." }],
      blockers: [],
      preview_writes: [],
      preview_external_effects: [],
      execute_writes: ["record durable deprecation evidence"],
      execute_external_effects: ["ask the signer to sign one certificate"],
      recovery_steps: ["revoke the exact issued serial"],
      verification_steps: ["verify the returned certificate"],
      cli_argv: ["trstctl", "secrets", "pki", "-f", "pki-request.json"],
      secret_data_handling: "The control plane returns the private key once.",
    });
    await user.selectOptions(legacyForm.getByLabelText("Key custody"), "legacy");
    await user.type(legacyForm.getByLabelText("Common name"), "legacy.internal");
    expect(legacyForm.getByRole("link", { name: /Review every legacy use in Audit/i })).toHaveAttribute("href", "/audit?type=issuance.server_side_keygen");
    await user.click(legacyForm.getByRole("button", { name: /review without issuing/i }));
    expect(await legacyForm.findByText("Audit evidence is available.")).toBeInTheDocument();
    await user.click(legacyForm.getByRole("button", { name: /issue reviewed certificate/i }));
    await waitFor(() =>
      expect(apiMock.issuePKISecret).toHaveBeenCalledWith({
        common_name: "legacy.internal",
        ttl_seconds: 900,
        preview_fingerprint: "sha256:reviewed-legacy",
      }),
    );
    expect(await screen.findByText(/PKI bundle pki-01/i)).toBeInTheDocument();
    expect(screen.getByText(/BEGIN PRIVATE KEY/)).toBeInTheDocument();

    cleanup();
    renderSecrets("/secrets/access");
    const loginForm = within(await screen.findByRole("form", { name: "Machine login test" }));
    await user.click(loginForm.getByRole("button", { name: "Review login test" }));
    await loginForm.findByText("sha256:reviewed-machine-login");
    await user.type(loginForm.getByLabelText("Credential"), "tenant-bound-machine-token");
    await user.click(loginForm.getByRole("button", { name: "Test reviewed login" }));

    await waitFor(() =>
      expect(apiMock.machineLogin).toHaveBeenCalledWith({
        method: "token",
        credential: "tenant-bound-machine-token",
        preview_fingerprint: "sha256:reviewed-machine-login",
      }),
    );
    expect(screen.getByText("sess-1")).toBeInTheDocument();
    expect(screen.getByText("svc-api")).toBeInTheDocument();
    expect(loginForm.queryByLabelText("Credential")).not.toBeInTheDocument();
    expect(screen.queryByText("tenant-bound-machine-token")).not.toBeInTheDocument();

    cleanup();
    renderSecrets("/secrets/sharing");
    await user.click(await screen.findByRole("button", { name: "Open one-time sharing" }));
    const shareForm = within(await screen.findByRole("form", { name: "Create one-time share" }));
    await user.type(shareForm.getByLabelText("Value to share"), "share-this-once");
    await user.click(shareForm.getByRole("button", { name: /review without creating/i }));
    await waitFor(() => expect(apiMock.previewShare).toHaveBeenCalledWith({ ttl_seconds: 300 }));
    await user.click(shareForm.getByRole("button", { name: /create reviewed share/i }));
    await waitFor(() =>
      expect(apiMock.createShare).toHaveBeenCalledWith(
        { value: "share-this-once", ttl_seconds: 300, preview_fingerprint: "sha256:reviewed-share" },
        expect.any(String),
      ),
    );
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

  it("reviews sharing without sending the value and reuses one recovery key after an ambiguous create", async () => {
    const user = userEvent.setup();
    apiMock.createShare
      .mockRejectedValueOnce(new TypeError("network connection interrupted"))
      .mockResolvedValueOnce({ token: "SHARE-TOKEN-RECOVERED", expires_at: "2026-06-19T13:30:00Z" });
    renderSecrets("/secrets/sharing");
    await user.click(await screen.findByRole("button", { name: "Open one-time sharing" }));
    const form = within(await screen.findByRole("form", { name: "Create one-time share" }));
    await user.type(form.getByLabelText("Value to share"), "recover-this-without-leaking");

    await user.click(form.getByRole("button", { name: "Review without creating" }));
    await waitFor(() => expect(apiMock.previewShare).toHaveBeenCalledWith({ ttl_seconds: 300 }));
    expect(apiMock.createShare).not.toHaveBeenCalled();
    expect(await form.findByText("Nothing has been stored or sent yet.")).toBeInTheDocument();
    expect(form.getByText("Sensitive secret changes use the configured dual-control approval queue.")).toBeInTheDocument();

    await user.click(form.getByRole("button", { name: "Create reviewed share" }));
    expect(await form.findByText(/The server may have created the share/)).toBeInTheDocument();
    expect(apiMock.createShare).toHaveBeenCalledTimes(1);
    const firstRecoveryKey = apiMock.createShare.mock.calls[0]?.[1];
    expect(firstRecoveryKey).toEqual(expect.any(String));

    await user.click(form.getByRole("button", { name: "Retry same reviewed share" }));
    await waitFor(() => expect(apiMock.createShare).toHaveBeenCalledTimes(2));
    expect(apiMock.createShare.mock.calls[1]?.[1]).toBe(firstRecoveryKey);
    expect(apiMock.createShare.mock.calls[1]?.[0]).toEqual({
      value: "recover-this-without-leaking",
      ttl_seconds: 300,
      preview_fingerprint: "sha256:reviewed-share",
    });
    expect(await screen.findByText("SHARE-TOKEN-RECOVERED")).toBeInTheDocument();
    expect(screen.queryByText("recover-this-without-leaking")).not.toBeInTheDocument();
    expect(screen.getByText("Secret-change approvals")).toBeInTheDocument();
    expect(localStorage.length).toBe(0);
    expect(sessionStorage.length).toBe(0);
  });

  it("shows the fail-closed disabled state when secrets API or KEK is unavailable", async () => {
    apiMock.secretPage.mockRejectedValueOnce(new ApiError(503, JSON.stringify({ detail: "secrets.enable_api disabled or KEK missing" })));
    renderSecrets();

    expect(await screen.findByText("Secrets API unavailable or disabled")).toBeInTheDocument();
    expect(screen.getByText(/secrets.enable_api disabled or KEK missing/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /add secret/i })).toBeDisabled();
    expect(screen.queryByRole("form", { name: /create secret/i })).not.toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Secret urgency is not fully known" })).toBeInTheDocument();
    expect(screen.getByText(/Retry before treating this workspace as healthy/)).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Some secret checks are turned off" })).not.toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "No urgent secrets work" })).not.toBeInTheDocument();
    expect(screen.queryByRole("list", { name: "Secrets and access health" })).not.toBeInTheDocument();
  });

  it("preflights unavailable optional Secrets APIs while preserving independent posture reads", async () => {
    const unvaulted = unvaultedSecretPostureFixture();
    unvaulted.summary.leaked_secret_findings = 0;
    apiMock.unvaultedSecrets.mockResolvedValueOnce(unvaulted);
    renderSecretsWithRuntime(secretsRuntime(false));

    expect((await screen.findAllByText(/native secret store is turned off/i)).length).toBeGreaterThan(0);
    await waitFor(() => {
      expect(apiMock.secretRepositoryScanning).toHaveBeenCalledTimes(1);
      expect(apiMock.thirdPartySecretScanning).toHaveBeenCalledTimes(1);
      expect(apiMock.secretSyncTargets).toHaveBeenCalledTimes(1);
      expect(apiMock.cloudSecretManagers).toHaveBeenCalledTimes(1);
      expect(apiMock.kubernetesSecretOperator).toHaveBeenCalledTimes(1);
      expect(apiMock.secretWorkloadInjection).toHaveBeenCalledTimes(1);
      expect(apiMock.unvaultedSecrets).toHaveBeenCalledTimes(1);
    });
    expect(apiMock.secretPage).not.toHaveBeenCalled();
    expect(apiMock.secretRotationSchedules).not.toHaveBeenCalled();
    expect(apiMock.machineAuthMethods).not.toHaveBeenCalled();
    expect(apiMock.machineSessions).not.toHaveBeenCalled();
    expect(screen.getByRole("button", { name: /add secret/i })).toBeDisabled();
    expect(screen.getByRole("heading", { name: "Some secret checks are turned off" })).toBeInTheDocument();
    expect(screen.getByText(/The leak and integration checks shown here are still live/)).toBeInTheDocument();
    expect(screen.queryByText(/Retry before treating this workspace as healthy/)).not.toBeInTheDocument();
    expect(document.body.textContent).not.toContain("secrets.. Secret");
  });

  it("restores each optional Secrets read when the runtime capability view allows it", async () => {
    renderSecretsWithRuntime(secretsRuntime(true));

    await waitFor(() => {
      expect(apiMock.secretPage).toHaveBeenCalledTimes(1);
      expect(apiMock.secretRotationSchedules).toHaveBeenCalledTimes(1);
      expect(apiMock.machineAuthMethods).toHaveBeenCalledTimes(1);
      expect(apiMock.machineSessions).toHaveBeenCalledTimes(1);
    });
    expect(await screen.findByText("app/db/password")).toBeInTheDocument();
    expect(screen.queryByText(nativeStoreUnavailableDetail)).not.toBeInTheDocument();
  });

  it("keeps independently served ephemeral API keys usable when the native secret store is unavailable", async () => {
    const user = userEvent.setup();
    apiMock.secretPage.mockRejectedValueOnce(new ApiError(503, JSON.stringify({ detail: "secrets.enable_api disabled or KEK missing" })));
    renderSecrets("/secrets/sharing");

    expect(await screen.findByText("Secrets API unavailable or disabled")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Open temporary access" }));
    expect(await screen.findByText(/Temporary API keys use the access service/)).toBeInTheDocument();

    const form = within(screen.getByRole("form", { name: "Review ephemeral API key" }));
    const submit = form.getByRole("button", { name: "Review temporary key" });
    expect(submit).toBeEnabled();
    await user.type(form.getByLabelText("Machine subject"), "ci/deploy-preview");
    await user.click(submit);

    await waitFor(() =>
      expect(apiMock.previewEphemeralAPIKey).toHaveBeenCalledWith({
        subject: "ci/deploy-preview",
        scopes: ["access:read"],
        ttl_seconds: 900,
      }),
    );
    await user.click(await screen.findByRole("button", { name: "Issue reviewed key" }));
    await waitFor(() => expect(apiMock.issueEphemeralAPIKey).toHaveBeenCalled());
    expect(await screen.findByText("epk_live_reveal_once_123")).toBeInTheDocument();
  });

  it("keeps independently served Transit encryption usable when the native secret store is unavailable", async () => {
    const user = userEvent.setup();
    apiMock.secretPage.mockRejectedValueOnce(new ApiError(503, JSON.stringify({ detail: "secrets.enable_api disabled or KEK missing" })));
    renderSecrets("/secrets/engines");

    expect(await screen.findByText("Secrets API unavailable or disabled")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Open encryption and signing" }));
    expect(await screen.findByText(/Transit uses the encryption service/)).toBeInTheDocument();

    const keyForm = within(screen.getByRole("form", { name: "Create a Transit key" }));
    await user.type(keyForm.getByLabelText("Key name"), "payments-pii");
    await user.click(keyForm.getByRole("button", { name: "Create key" }));
    await waitFor(() => expect(apiMock.createTransitKey).toHaveBeenCalledWith({ name: "payments-pii", kind: "aead" }));

    const form = within(screen.getByRole("form", { name: "Transit encrypt and decrypt" }));
    await user.type(form.getByLabelText("Plaintext"), "hello transit");
    const encrypt = form.getByRole("button", { name: /encrypt/i });
    expect(encrypt).toBeEnabled();
    await user.click(encrypt);

    await waitFor(() =>
      expect(apiMock.encryptTransit).toHaveBeenCalledWith({
        key: "payments-pii",
        plaintext: "aGVsbG8gdHJhbnNpdA==",
      }),
    );
    expect((await screen.findAllByText("trst:v1:ciphertext")).length).toBeGreaterThan(0);
  });

  it("renders the shared grid empty state for an enabled store with no metadata", async () => {
    apiMock.secretPage.mockResolvedValueOnce({ items: [] });
    renderSecrets();

    expect(await screen.findByText("No secrets stored yet")).toBeInTheDocument();
    expect(screen.getByText(/Only the name and version return/)).toBeInTheDocument();
  });
});

// ------------------------------------------------------------------ C-S1 ----
// DA-02 interim: Job 2 — create, grant, verify — completes in-console with
// zero backend changes. The grant console mints scoped credentials over the
// existing idempotent /access and /ephemeral endpoints, lists and revokes
// them, and the old "isn't in the console yet" dead-end shrinks to the
// method/session half that genuinely waits for C-S2..C-S4.

describe("secrets access grant console (C-S1 / DA-02 interim)", () => {
  beforeEach(() => primeSecretsMocks());

  async function openAccessTab() {
    const user = userEvent.setup();
    renderSecrets("/secrets/access");
    await screen.findByRole("heading", { name: "Grant workload access" });
    return user;
  }

  it("mints a scoped standing token for a picked workload and reveals it once", async () => {
    const user = await openAccessTab();
    const grant = within(await screen.findByRole("form", { name: "Grant workload access" }));

    const subject = grant.getByLabelText("Workload / subject");
    await user.type(subject, "wl-1111");
    // Scopes default to secrets:read — the least-privilege Job 2 grant.
    expect(grant.getByLabelText(/Scopes/)).toHaveValue("secrets:read");
    await user.click(grant.getByRole("button", { name: "Grant access" }));

    await waitFor(() => expect(apiMock.createAPIToken).toHaveBeenCalledWith({ subject: "wl-1111", scopes: ["secrets:read"] }));
    expect(await screen.findByText("trst_REVEAL_ONCE_abc")).toBeInTheDocument();
    expect(screen.getByText(/never shown again/i)).toBeInTheDocument();
    // Ledger refreshes after the mint.
    expect(apiMock.apiTokens.mock.calls.length).toBeGreaterThan(1);
  });

  it("verifies the minted bearer token with a real scoped secret read and never renders the value", async () => {
    const storageSpy = vi.spyOn(Storage.prototype, "setItem");
    const user = await openAccessTab();
    const grant = within(await screen.findByRole("form", { name: "Grant workload access" }));

    await user.type(grant.getByLabelText("Workload / subject"), "wl-1111");
    await user.click(grant.getByRole("button", { name: "Grant access" }));
    await user.click(await screen.findByRole("button", { name: "Verify scoped read" }));

    await waitFor(() => expect(apiMock.getSecretWithToken).toHaveBeenCalledWith("app/db/password", "trst_REVEAL_ONCE_abc"));
    expect(await screen.findByText(/Scoped read passed for app\/db\/password; version 3/)).toBeInTheDocument();
    expect(screen.queryByText("WORKLOAD-SECRET")).not.toBeInTheDocument();
    expect(storageSpy).not.toHaveBeenCalled();
  });

  it("offers the identity roster on the subject picker", async () => {
    await openAccessTab();
    const subject = await screen.findByLabelText("Workload / subject");
    const listId = subject.getAttribute("list");
    expect(listId).toBeTruthy();
    await waitFor(() => {
      const options = Array.from(document.getElementById(listId as string)?.querySelectorAll("option") ?? []);
      expect(options.map((option) => option.getAttribute("value"))).toContain("wl-1111");
    });
  });

  it("mints a TTL-bound ephemeral key when time-bound is selected", async () => {
    const user = await openAccessTab();
    const grant = within(await screen.findByRole("form", { name: "Grant workload access" }));

    await user.type(grant.getByLabelText("Workload / subject"), "wl-1111");
    await user.click(grant.getByLabelText(/Time-bound/));
    await user.clear(grant.getByLabelText("TTL seconds"));
    await user.type(grant.getByLabelText("TTL seconds"), "900");
    await user.click(grant.getByRole("button", { name: "Grant access" }));

    await waitFor(() => expect(apiMock.issueEphemeralAPIKey).toHaveBeenCalledWith({ subject: "wl-1111", scopes: ["secrets:read"], ttl_seconds: 900 }));
    expect(await screen.findByText("epk_live_reveal_once_123")).toBeInTheDocument();
    expect(apiMock.createAPIToken).not.toHaveBeenCalled();
  });

  it("lists granted tokens and revokes one", async () => {
    const user = await openAccessTab();
    // Ledger renders both rows, revoked one labeled as such.
    expect(await screen.findByText("wl-1111")).toBeInTheDocument();
    expect(screen.getByText("old-bot")).toBeInTheDocument();

    const row = screen.getByText("wl-1111").closest("tr") as HTMLTableRowElement;
    await user.click(within(row).getByRole("button", { name: "Revoke" }));
    await waitFor(() => expect(apiMock.revokeAPIToken).toHaveBeenCalledWith("tok-1"));
  });

  it("contains zero 'isn't in the console yet' text (C-S4 exit gate)", async () => {
    await openAccessTab();
    await screen.findByRole("heading", { name: "Auth methods" });
    expect(screen.queryByText(/isn't in the console yet/)).not.toBeInTheDocument();
  });

  it("keeps the login verify step working beside the grant flow", async () => {
    const user = await openAccessTab();
    const loginForm = within(screen.getByRole("form", { name: "Machine login test" }));
    await user.click(loginForm.getByRole("button", { name: "Review login test" }));
    await loginForm.findByText("sha256:reviewed-machine-login");
    await user.type(loginForm.getByLabelText("Credential"), "cred-1");
    await user.click(loginForm.getByRole("button", { name: "Test reviewed login" }));
    await waitFor(() =>
      expect(apiMock.machineLogin).toHaveBeenCalledWith({
        method: "token",
        credential: "cred-1",
        preview_fingerprint: "sha256:reviewed-machine-login",
      }),
    );
    expect(await screen.findByText("sess-1")).toBeInTheDocument();
  });
});

// ------------------------------------------------------------------ C-S4 ----
// DA-02 faithful: the auth-method console over the C-S2/C-S3 endpoints. All
// four promised sub-surfaces exist (methods, audience rules, session ledger,
// revoked view) and the placeholder class is dead.

describe("secrets auth-method console (C-S4 / DA-02)", () => {
  beforeEach(() => primeSecretsMocks());

  async function openAccessTab() {
    const user = userEvent.setup();
    renderSecrets("/secrets/access");
    await screen.findByRole("heading", { name: "Grant workload access" });
    return user;
  }

  it("renders the configured methods with issuer, audience, source, and overlay state", async () => {
    await openAccessTab();
    expect(await screen.findByText("ci-jwt")).toBeInTheDocument();
    expect(screen.getByText("https://ci.example.test")).toBeInTheDocument();
    expect(screen.getByText("builtin")).toBeInTheDocument();
    // The overlay state renders per method: ci-jwt is disabled in the fixture.
    const jwtRow = screen.getByText("ci-jwt").closest("tr") as HTMLTableRowElement;
    expect(within(jwtRow).getByText("disabled")).toBeInTheDocument();
    const tokenRow = screen.getAllByText("token")[0].closest("tr") as HTMLTableRowElement;
    expect(within(tokenRow).getByText("enabled")).toBeInTheDocument();
  });

  it("reviews one exact method before accepting a credential, executes it once, and verifies the durable session", async () => {
    const user = await openAccessTab();
    const loginForm = within(screen.getByRole("form", { name: "Machine login test" }));

    expect(loginForm.getByLabelText("Method")).toHaveValue("token");
    expect(loginForm.queryByLabelText("Credential")).not.toBeInTheDocument();
    await user.click(loginForm.getByRole("button", { name: "Review login test" }));

    await waitFor(() => expect(apiMock.previewMachineLogin).toHaveBeenCalledWith({ method: "token" }));
    expect(await loginForm.findByText("The credential and issued session are bound to this tenant.")).toBeInTheDocument();
    expect(loginForm.getByText("The token method accepts new logins.")).toBeInTheDocument();
    expect(loginForm.getByText(/Preview never receives a credential/)).toBeInTheDocument();
    expect(loginForm.getByText("sha256:reviewed-machine-login")).toBeInTheDocument();

    const credential = loginForm.getByLabelText("Credential");
    await user.type(credential, "tenant-bound-machine-token");
    await user.click(loginForm.getByRole("button", { name: "Test reviewed login" }));
    await waitFor(() =>
      expect(apiMock.machineLogin).toHaveBeenCalledWith({
        method: "token",
        credential: "tenant-bound-machine-token",
        preview_fingerprint: "sha256:reviewed-machine-login",
      }),
    );
    expect(await loginForm.findByText("sess-1")).toBeInTheDocument();
    expect(loginForm.getByText("svc-api")).toBeInTheDocument();
    const bearer = await loginForm.findByText("trst_MACHINE_SESSION_REVEAL_ONCE");
    const reveal = bearer.closest(".ui-panel") as HTMLElement;
    expect(within(reveal).getByText("One-time machine session bearer")).toBeInTheDocument();
    await user.click(within(reveal).getByRole("button", { name: "Dismiss" }));
    expect(loginForm.queryByText("trst_MACHINE_SESSION_REVEAL_ONCE")).not.toBeInTheDocument();
    expect(loginForm.getByText("sess-1")).toBeInTheDocument();
    expect(screen.queryByText("tenant-bound-machine-token")).not.toBeInTheDocument();
    expect(apiMock.machineSessions.mock.calls.length).toBeGreaterThan(1);
  });

  it("shows a disabled method's exact blockers without accepting or sending a credential", async () => {
    apiMock.previewMachineLogin.mockResolvedValueOnce({
      capability: "F58",
      operation: "test_machine_login",
      ready: false,
      effect_free: true,
      method: { name: "ci-jwt", type: "jwt", source: "config", jwks_configured: true, disabled: true },
      tenant_binding: "The credential and issued session are bound to this tenant.",
      credential_format: "A signed JWT with the configured issuer, audience, expiry, and tenant claim.",
      session_ttl_seconds: 3600,
      required_permission: "secrets:read",
      request_fingerprint: "sha256:blocked-machine-login",
      prerequisites: [
        { id: "method_configured", ready: true, detail: "The ci-jwt method is configured." },
        {
          id: "method_enabled",
          ready: false,
          detail: "The ci-jwt method is disabled and refuses new sessions.",
          remediation: "Enable ci-jwt, then preview again.",
        },
      ],
      blockers: ["Method ci-jwt is disabled. Enable it before testing a credential."],
      preview_reads: ["read the tenant-scoped method projection"],
      preview_writes: [],
      preview_external_effects: [],
      execute_writes: [],
      execute_external_effects: [],
      recovery_steps: ["Enable ci-jwt, then build a new review."],
      verification_steps: ["Confirm no session was issued while the method was disabled."],
      cli_argv: ["trstctl", "secrets", "login", "preview", "-f", "machine-login.json"],
      secret_data_handling: "Preview never receives a credential.",
    });
    const user = await openAccessTab();
    const loginForm = within(screen.getByRole("form", { name: "Machine login test" }));
    await user.selectOptions(loginForm.getByLabelText("Method"), "ci-jwt");
    await user.click(loginForm.getByRole("button", { name: "Review login test" }));

    expect(await loginForm.findByText("This method is blocked")).toBeInTheDocument();
    expect(loginForm.getByText("Method ci-jwt is disabled. Enable it before testing a credential.")).toBeInTheDocument();
    expect(loginForm.queryByLabelText("Credential")).not.toBeInTheDocument();
    expect(loginForm.queryByRole("button", { name: "Test reviewed login" })).not.toBeInTheDocument();
    expect(apiMock.machineLogin).not.toHaveBeenCalled();
  });

  it("clears a rejected credential, preserves a usable review, and succeeds after correction", async () => {
    apiMock.machineLogin.mockRejectedValueOnce(new ApiError(401, JSON.stringify({ detail: "machine login failed" })));
    const user = await openAccessTab();
    const loginForm = within(screen.getByRole("form", { name: "Machine login test" }));
    await user.click(loginForm.getByRole("button", { name: "Review login test" }));
    const credential = await loginForm.findByLabelText("Credential");
    await user.type(credential, "rejected-credential");
    await user.click(loginForm.getByRole("button", { name: "Test reviewed login" }));

    await waitFor(() => expect(apiMock.machineLogin).toHaveBeenCalledTimes(1));
    expect(loginForm.getByLabelText("Credential")).toHaveValue("");
    expect(loginForm.getByText("sha256:reviewed-machine-login")).toBeInTheDocument();
    expect(screen.queryByText("rejected-credential")).not.toBeInTheDocument();

    await user.type(loginForm.getByLabelText("Credential"), "corrected-credential");
    await user.click(loginForm.getByRole("button", { name: "Test reviewed login" }));
    await waitFor(() => expect(apiMock.machineLogin).toHaveBeenCalledTimes(2));
    expect(await loginForm.findByText("sess-1")).toBeInTheDocument();
  });

  it("invalidates a server-rejected stale review before another credential can be entered", async () => {
    apiMock.machineLogin.mockRejectedValueOnce(
      new ApiError(409, JSON.stringify({ detail: "the reviewed machine-login plan changed; review the method again" })),
    );
    const user = await openAccessTab();
    const loginForm = within(screen.getByRole("form", { name: "Machine login test" }));
    await user.click(loginForm.getByRole("button", { name: "Review login test" }));
    await user.type(await loginForm.findByLabelText("Credential"), "stale-plan-credential");
    await user.click(loginForm.getByRole("button", { name: "Test reviewed login" }));

    expect(await loginForm.findByText("The method changed. Review the new method before entering a credential.")).toBeInTheDocument();
    expect(loginForm.queryByLabelText("Credential")).not.toBeInTheDocument();
    expect(loginForm.getByRole("button", { name: "Review login test" })).toBeInTheDocument();
    expect(screen.queryByText("stale-plan-credential")).not.toBeInTheDocument();
  });

  it("disables and re-enables a method through the overlay endpoints", async () => {
    const user = await openAccessTab();
    const tokenRow = (await screen.findByText("builtin")).closest("tr") as HTMLTableRowElement;
    await user.click(within(tokenRow).getByRole("button", { name: "Disable" }));
    await waitFor(() => expect(apiMock.disableMachineAuthMethod).toHaveBeenCalledWith("token"));
    // The projection refreshes after the action.
    expect(apiMock.machineAuthMethods.mock.calls.length).toBeGreaterThan(1);

    const jwtRow = screen.getByText("ci-jwt").closest("tr") as HTMLTableRowElement;
    await user.click(within(jwtRow).getByRole("button", { name: "Enable" }));
    await waitFor(() => expect(apiMock.enableMachineAuthMethod).toHaveBeenCalledWith("ci-jwt"));
  });

  it("renders the issued-session ledger with the revoked view inline", async () => {
    await openAccessTab();
    expect(await screen.findByText("payments-bot")).toBeInTheDocument();
    const revokedRow = screen.getByText("retired-bot").closest("tr") as HTMLTableRowElement;
    expect(within(revokedRow).getByText("revoked")).toBeInTheDocument();
    // Revoked rows carry no revoke action; active rows do.
    expect(within(revokedRow).queryByRole("button", { name: "Revoke" })).not.toBeInTheDocument();
  });

  it("revokes an active session and refreshes the ledger", async () => {
    const user = await openAccessTab();
    const activeRow = (await screen.findByText("payments-bot")).closest("tr") as HTMLTableRowElement;
    await user.click(within(activeRow).getByRole("button", { name: "Revoke" }));
    await waitFor(() => expect(apiMock.revokeMachineSession).toHaveBeenCalledWith("sess-active-1"));
    expect(apiMock.machineSessions.mock.calls.length).toBeGreaterThan(1);
  });

  it("degrades honestly when the ledger endpoints are not served", async () => {
    apiMock.machineAuthMethods.mockRejectedValue(new ApiError(404, "not enabled"));
    apiMock.machineSessions.mockRejectedValue(new ApiError(404, "not enabled"));
    await openAccessTab();
    expect(await screen.findByText(/Method projection unavailable/)).toBeInTheDocument();
    expect(screen.getByText(/Session ledger unavailable/)).toBeInTheDocument();
  });
});
