import { describe, expect, it, vi, beforeEach } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { CodeSigning } from "@/pages/CodeSigning";
import { AppQueryProvider } from "@/lib/query";
import type { CapabilityView, CapabilityViewItem } from "@/lib/api-types.gen";
import { CapabilityFixtureProvider } from "@/lib/capabilities";
import { ApiError } from "@/lib/api";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    previewCode: vi.fn(),
    previewCodeKeyless: vi.fn(),
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
  for (const mock of Object.values(apiMock)) mock.mockReset();
  const preview = {
    capability: "F50",
    operation: "sign_code_artifact",
    mode: "key",
    ready: true,
    effect_free: true,
    artifact_type: "container",
    digest_sha256: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    key_id: "key-1",
    required_permission: "keys:write",
    request_fingerprint: `sha256:${"a".repeat(64)}`,
    configuration_fingerprint: `sha256:${"b".repeat(64)}`,
    signing_algorithm: "ECDSA-P256",
    transparency_destination: "transparency.rekor",
    approval_required: false,
    blockers: [],
    preview_reads: ["read signer metadata"],
    preview_writes: [],
    preview_external_effects: [],
    execute_writes: ["append one immutable command"],
    execute_external_effects: ["ask the isolated signer"],
    recovery_steps: ["retry the same request"],
    verification_steps: ["verify the signature"],
    cli_argv: ["trstctl-cli", "code-signing", "preview", "-f", "code-signing.json"],
    secret_data_handling: "Artifact bytes and private keys never enter the browser.",
  } as const;
  apiMock.previewCode.mockResolvedValue(preview);
  apiMock.previewCodeKeyless.mockResolvedValue({
    ...preview,
    operation: "sign_code_artifact_keyless",
    mode: "keyless",
    key_id: undefined,
    identity_method: "github_oidc",
  });
  apiMock.signCode.mockReset().mockResolvedValue({
    algorithm: "ECDSA-P256",
    artifact_type: "container",
    key_id: "key-1",
    public_key_der: "BASE64DER",
    signature: "BASE64SIG",
    transparency_destination: "transparency.rekor",
  });
  apiMock.signCodeKeyless.mockReset().mockResolvedValue({
    algorithm: "ECDSA-P256",
    artifact_type: "container",
    fulcio_issuer: "https://oauth2.example",
    public_key_der: "BASE64DER",
    signature: "BASE64SIG",
  });
  apiMock.codeSigningIdentities.mockResolvedValue({
    total: 2,
    verified_count: 1,
    not_published_count: 0,
    items: [
      {
        operation_id: "sign-failed",
        request_hash: "a".repeat(64),
        mode: "managed",
        status: "failed",
        transparency: "failed",
        last_error: "Rekor publication failed",
        transparency_error: "Rekor unavailable",
        created_at: "2026-08-24T10:00:00Z",
        updated_at: "2026-08-24T10:01:00Z",
      },
      {
        operation_id: "sign-verified",
        request_hash: "b".repeat(64),
        mode: "keyless",
        status: "completed",
        transparency: "verified",
        created_at: "2026-08-24T09:00:00Z",
        updated_at: "2026-08-24T09:01:00Z",
      },
    ],
  });
  apiMock.approvalRequests.mockResolvedValue([
    {
      id: "approval-1",
      action: "sign",
      approval_count: 1,
      required_approvals: 2,
      created_at: "2026-08-24T10:00:00Z",
      expires_at: "2026-08-25T10:00:00Z",
      evidence_refs: [],
      intent_digest: "intent-1",
      requester: "release-bot",
      resource_id: "release-2026-08",
      resource_kind: "code_signing",
      resource_name: "release-2026-08",
      status: "pending",
      target_version: "1",
    },
  ]);
  apiMock.protocolStatuses.mockResolvedValue({
    source: "public_responder_probe",
    checked_at: "2026-08-24T10:02:00Z",
    items: [{ protocol: "tsa", endpoint: "/tsa", enabled: true, served: true, status_code: 200 }],
  });
});

function codeSigningCapability(capabilityId: "F33" | "F50", operationId: string, available: boolean): CapabilityViewItem {
  const detail = "This operation is unavailable because its runtime dependency is not configured.";
  return {
    capability_id: capabilityId,
    name: capabilityId === "F33" ? "Just-in-time issuance with approval flows" : "Code-signing service",
    purpose: "Prove that Software Trust preflights optional overview reads.",
    tool: capabilityId === "F33" ? "operations" : "software_trust",
    classification: "primary",
    console_route: capabilityId === "F33" ? "/request" : "/codesign",
    maturity: "partial_workflow",
    release_blocking: true,
    edition: "core",
    runtime_state: available ? "available" : "unavailable",
    authorization_state: available ? "full" : "none",
    dependency_state: "none",
    dependencies: [],
    stages: [{ name: "observe", completion: available ? "complete" : "blocked", ...(available ? {} : { reason: detail }) }],
    actions: {
      allowed: available
        ? capabilityId === "F50"
          ? ["listCodeSigningIdentities", "previewCodeArtifact", "previewCodeArtifactKeyless", "signCodeArtifact", "signCodeArtifactKeyless"]
          : [operationId]
        : [],
      scoped: [],
      denied: [],
      unavailable: available
        ? []
        : (capabilityId === "F50"
            ? ["listCodeSigningIdentities", "previewCodeArtifact", "previewCodeArtifactKeyless", "signCodeArtifact", "signCodeArtifactKeyless"]
            : [operationId]
          ).map((id) => ({ operation_id: id, code: "dependency_not_configured" as const, detail })),
    },
  };
}

function codeSigningRuntime(options: { approvals?: boolean; operations?: boolean } = {}): CapabilityView {
  return {
    schema_version: 2,
    contract_schema_version: 3,
    enforcement_note: "The server checks every operation again when it executes.",
    license: { tier: "community", state: "community" },
    operations: [],
    items: [
      codeSigningCapability("F50", "listCodeSigningIdentities", options.operations ?? true),
      codeSigningCapability("F33", "listApprovalRequests", options.approvals ?? true),
    ],
  };
}

function renderPage(view?: CapabilityView) {
  const page = (
    <AppQueryProvider>
      <MemoryRouter>
        <CodeSigning />
      </MemoryRouter>
    </AppQueryProvider>
  );
  return render(view ? <CapabilityFixtureProvider view={view}>{page}</CapabilityFixtureProvider> : page);
}

describe("code signing console", () => {
  it("reviews a key-backed request before signing and renders the served signature receipt", async () => {
    const user = userEvent.setup();
    renderPage();
    expect(screen.getByRole("heading", { name: "Software Trust" })).toBeInTheDocument();
    expect(screen.getByText(/what software-signing work needs attention/i)).toBeInTheDocument();
    await user.type(screen.getByLabelText("Artifact digest"), "sha256:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    await user.type(screen.getByLabelText("Managed key id"), "key-1");
    await user.click(screen.getByRole("button", { name: "Review signing plan" }));

    await waitFor(() =>
      expect(apiMock.previewCode).toHaveBeenCalledWith({
        artifact_type: "container",
        digest: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
        key_id: "key-1",
      }),
    );
    expect(await screen.findByText("This exact signing request is ready")).toBeInTheDocument();
    expect(screen.getByText(/no signature, event, database row/i)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Sign this reviewed digest" }));

    await waitFor(() =>
      expect(apiMock.signCode).toHaveBeenCalledWith(
        {
          artifact_type: "container",
          digest: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
          key_id: "key-1",
          preview_fingerprint: `sha256:${"a".repeat(64)}`,
        },
        expect.stringMatching(/^codesign-/),
      ),
    );
    expect(await screen.findByText("Signature receipt")).toBeInTheDocument();
    expect(screen.getAllByText("ECDSA-P256").length).toBeGreaterThan(0);
    expect(screen.getByText("BASE64SIG")).toBeInTheDocument();
    expect(screen.getAllByText("transparency.rekor").length).toBeGreaterThan(0);
    expect(screen.getByRole("link", { name: "Download signature" })).toHaveAttribute("download", "artifact.sig");
    // The signer boundary holds: no private key material ever reaches the browser.
    expect(screen.queryByText(/BEGIN .* PRIVATE KEY/)).not.toBeInTheDocument();
  });

  it("invalidates the review after an input changes and requires a fresh server preview", async () => {
    const user = userEvent.setup();
    renderPage();
    const digest = screen.getByLabelText("Artifact digest");
    await user.type(digest, "0".repeat(64));
    await user.type(screen.getByLabelText("Managed key id"), "key-1");
    await user.click(screen.getByRole("button", { name: "Review signing plan" }));
    expect(await screen.findByText("This exact signing request is ready")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Previous" }));
    const currentDigest = screen.getByLabelText("Artifact digest");
    await user.clear(currentDigest);
    await user.type(currentDigest, "1".repeat(64));
    expect(screen.queryByRole("button", { name: "Sign this reviewed digest" })).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Review signing plan" }));
    await waitFor(() => expect(apiMock.previewCode).toHaveBeenCalledTimes(2));
    expect(apiMock.previewCode.mock.calls[1]?.[0]).toMatchObject({ digest: "ERERERERERERERERERERERERERERERERERERERERERE=" });
  });

  it("retries an ambiguous response with the identical request and idempotency key", async () => {
    const user = userEvent.setup();
    apiMock.signCode.mockRejectedValueOnce(new Error("connection closed before response")).mockResolvedValueOnce({
      algorithm: "ECDSA-P256",
      artifact_type: "container",
      key_id: "key-1",
      public_key_der: "BASE64DER",
      signature: "BASE64SIG",
      transparency_destination: "transparency.rekor",
    });
    renderPage();
    await user.type(screen.getByLabelText("Artifact digest"), "0".repeat(64));
    await user.type(screen.getByLabelText("Managed key id"), "key-1");
    await user.click(screen.getByRole("button", { name: "Review signing plan" }));
    await user.click(await screen.findByRole("button", { name: "Sign this reviewed digest" }));
    expect(await screen.findByRole("button", { name: "Retry the same reviewed request" })).toBeInTheDocument();
    const firstCall = apiMock.signCode.mock.calls[0];
    await user.click(screen.getByRole("button", { name: "Retry the same reviewed request" }));
    await waitFor(() => expect(apiMock.signCode).toHaveBeenCalledTimes(2));
    expect(apiMock.signCode.mock.calls[1]).toEqual(firstCall);
  });

  it("throws away a stale review and uses a fresh idempotency key after re-review", async () => {
    const user = userEvent.setup();
    apiMock.signCode.mockRejectedValueOnce(new ApiError(409, JSON.stringify({ title: "Conflict", detail: "reviewed plan is stale" }))).mockResolvedValueOnce({
      algorithm: "ECDSA-P256",
      artifact_type: "container",
      key_id: "key-1",
      public_key_der: "BASE64DER",
      signature: "BASE64SIG",
      transparency_destination: "transparency.rekor",
    });
    renderPage();
    await user.type(screen.getByLabelText("Artifact digest"), "0".repeat(64));
    await user.type(screen.getByLabelText("Managed key id"), "key-1");
    await user.click(screen.getByRole("button", { name: "Review signing plan" }));
    await user.click(await screen.findByRole("button", { name: "Sign this reviewed digest" }));
    expect(await screen.findByText(/nothing was signed; review the current plan again/i)).toBeInTheDocument();
    const rejectedKey = apiMock.signCode.mock.calls[0]?.[1];

    await user.click(screen.getByRole("button", { name: "Review signing plan" }));
    await user.click(await screen.findByRole("button", { name: "Sign this reviewed digest" }));
    await waitFor(() => expect(apiMock.signCode).toHaveBeenCalledTimes(2));
    expect(apiMock.signCode.mock.calls[1]?.[1]).toMatch(/^codesign-/);
    expect(apiMock.signCode.mock.calls[1]?.[1]).not.toBe(rejectedKey);
    expect(await screen.findByText("Signature receipt")).toBeInTheDocument();
  });

  it("binds a keyless identity proof in preview without rendering the proof", async () => {
    const user = userEvent.setup();
    renderPage();
    await user.click(screen.getByRole("button", { name: "Verified keyless identity" }));
    await user.type(screen.getByLabelText("Artifact digest"), "0".repeat(64));
    await user.type(screen.getByLabelText("Short-lived identity proof"), "sensitive-oidc-proof");
    await user.click(screen.getByRole("button", { name: "Review signing plan" }));
    await waitFor(() => expect(apiMock.previewCodeKeyless).toHaveBeenCalledTimes(1));
    expect(apiMock.previewCodeKeyless.mock.calls[0]?.[0]).toMatchObject({ identity_payload: "c2Vuc2l0aXZlLW9pZGMtcHJvb2Y=" });
    expect(screen.queryByText("sensitive-oidc-proof")).not.toBeInTheDocument();
    expect(await screen.findByText("This exact signing request is ready")).toBeInTheDocument();
  });

  it("puts failed signing, approvals, timestamping, and recent outcomes before the signing control", async () => {
    renderPage();

    expect(await screen.findByRole("heading", { name: "2 Software Trust items need attention" })).toBeInTheDocument();
    const health = screen.getByRole("list", { name: "Software Trust health" });
    expect(screen.getByText("1 signing or transparency failure")).toBeInTheDocument();
    expect(screen.getByText("1 signing approval waiting")).toBeInTheDocument();
    expect(screen.getByText("Timestamping is serving")).toBeInTheDocument();
    expect(screen.getByText("Managed-key inventory is not exposed by this read model")).toBeInTheDocument();
    expect(within(health).getByText("2 recent signing operations")).toBeInTheDocument();

    const outcomes = screen.getByRole("table", { name: "Recent software-signing outcomes" });
    expect(within(outcomes).getByText("sign-failed")).toBeInTheDocument();
    expect(within(outcomes).getByText("Managed key")).toBeInTheDocument();
    expect(within(outcomes).getByText("Transparency failed")).toBeInTheDocument();
    expect(within(outcomes).getByText("Rekor publication failed")).toBeInTheDocument();
  });

  it("fails closed when the signing ledger cannot be read", async () => {
    apiMock.codeSigningIdentities.mockRejectedValue(new Error("ledger unavailable"));
    renderPage();

    expect(await screen.findByRole("heading", { name: "Software Trust urgency is not fully known" }, { timeout: 3_000 })).toBeInTheDocument();
    expect(screen.getAllByText("Signing outcomes are unavailable").length).toBeGreaterThan(0);
    expect(screen.queryByText("No Software Trust work needs attention")).not.toBeInTheDocument();
  });

  it("skips a known-unavailable approval queue while keeping independent Software Trust evidence live", async () => {
    renderPage(codeSigningRuntime({ approvals: false }));

    await waitFor(() => {
      expect(apiMock.codeSigningIdentities).toHaveBeenCalledTimes(1);
      expect(apiMock.protocolStatuses).toHaveBeenCalledTimes(1);
    });
    expect(apiMock.approvalRequests).not.toHaveBeenCalled();
    expect((await screen.findAllByText("Signing approvals are unavailable")).length).toBeGreaterThan(0);
  });

  it("restores the approval overview read when the exact runtime operation is available", async () => {
    renderPage(codeSigningRuntime());

    await waitFor(() => expect(apiMock.approvalRequests).toHaveBeenCalledTimes(1));
  });
});
