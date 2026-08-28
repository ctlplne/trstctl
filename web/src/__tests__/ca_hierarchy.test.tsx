import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { ApiError } from "@/lib/api";
import type { CapabilityView } from "@/lib/api-types.gen";
import { CapabilityFixtureProvider } from "@/lib/capabilities";
import { CAHierarchy } from "@/pages/CAHierarchy";
import { ToastProvider } from "@/components/ToastProvider";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    issuers: vi.fn(),
    profiles: vi.fn(),
    caDiscoveryInventory: vi.fn(),
    externalCAs: vi.fn(),
    issuerCapabilities: vi.fn(),
    previewCACeremony: vi.fn(),
    createCACeremony: vi.fn(),
    approveCACeremony: vi.fn(),
    importOfflineRootCA: vi.fn(),
    importExistingCA: vi.fn(),
    createOfflineIntermediateCSR: vi.fn(),
    importOfflineIntermediateCA: vi.fn(),
    previewCAAuthorityRotation: vi.fn(),
    rotateCAAuthority: vi.fn(),
    rekeyCAAuthority: vi.fn(),
    managedKeyCustody: vi.fn(),
    previewManagedKeyGeneration: vi.fn(),
    generateManagedKey: vi.fn(),
    rotateManagedKey: vi.fn(),
    revokeManagedKey: vi.fn(),
    zeroizeManagedKey: vi.fn(),
    issueExternalCA: vi.fn(),
    caAuthorities: vi.fn(),
    edgeSegmentPolicies: vi.fn(),
    edgeDelegations: vi.fn(),
    caRetirementChecklist: vi.fn(),
    retireCAKey: vi.fn(),
  },
}));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: apiMock };
});

function renderCAHierarchy(initialEntry = "/ca-hierarchy", runtime?: CapabilityView) {
  const page = (
    <MemoryRouter initialEntries={[initialEntry]}>
      <ToastProvider>
        <CAHierarchy />
      </ToastProvider>
    </MemoryRouter>
  );
  return render(runtime ? <CapabilityFixtureProvider view={runtime}>{page}</CapabilityFixtureProvider> : page);
}

function externalCAUnavailableRuntime(): CapabilityView {
  const detail = "No external CA service is configured in this deployment.";
  return {
    schema_version: 2,
    contract_schema_version: 3,
    enforcement_note: "The server checks again at execution.",
    license: { tier: "community", state: "community" },
    operations: [],
    items: [
      {
        capability_id: "F4",
        name: "CA-agnostic outbound issuance",
        purpose: "Issue through configured authorities.",
        tool: "certificates",
        classification: "primary",
        console_route: "/ca-hierarchy",
        maturity: "partial_workflow",
        release_blocking: false,
        edition: "core_with_licensed_extensions",
        runtime_state: "partially_available",
        authorization_state: "full",
        dependency_state: "none",
        dependencies: [],
        stages: [{ name: "observe", completion: "complete" }],
        actions: {
          allowed: ["listIssuers"],
          scoped: [],
          denied: [],
          unavailable: [
            { operation_id: "listExternalCAs", code: "dependency_not_configured", detail },
            { operation_id: "issueExternalCA", code: "dependency_not_configured", detail },
          ],
        },
      },
    ],
  };
}

describe("CA hierarchy and custody surface", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    for (const mock of Object.values(apiMock)) mock.mockReset();
    apiMock.caAuthorities.mockResolvedValue({ items: [] });
    apiMock.edgeSegmentPolicies.mockResolvedValue({ items: [], guidance: "" });
    apiMock.edgeDelegations.mockResolvedValue({ items: [], guidance: "" });
    apiMock.caRetirementChecklist.mockResolvedValue({
      key_id: "iss-root",
      blocked: true,
      accounted: 1,
      total: 2,
      outstanding: [{ kind: "credential", ref: "leaf-2", detail: "re-issue under the successor" }],
      guidance: "The isolated signer owns the final decision.",
    });
    apiMock.retireCAKey.mockResolvedValue({
      key_id: "iss-root",
      command_event_id: "vdec-command-1",
      status: "pending",
      ledger_position: 41,
      final_epoch: 7,
    });
    apiMock.issuers.mockReset().mockResolvedValue([
      {
        id: "iss-root",
        name: "Root CA",
        kind: "x509_ca",
        internal: true,
        chain: ["Root CA"],
        public_key: "-----BEGIN PUBLIC KEY-----ROOT-----END PUBLIC KEY-----",
      },
      {
        id: "iss-ssh",
        name: "SSH CA",
        kind: "ssh_ca",
        internal: false,
        chain: ["Root CA", "SSH CA"],
        public_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA",
      },
    ]);
    apiMock.profiles.mockReset().mockResolvedValue([]);
    apiMock.externalCAs.mockReset().mockResolvedValue([]);
    apiMock.issuerCapabilities.mockReset().mockResolvedValue({
      issuers: [
        {
          issuer: "letsencrypt",
          discover: false,
          issue: true,
          renew: true,
          revoke: true,
          key_handling: "requester_csr",
          validation: "acme_challenge",
          unattended_dv: true,
        },
        {
          issuer: "digicert",
          discover: false,
          issue: true,
          renew: true,
          revoke: false,
          key_handling: "requester_csr",
          validation: "organizational",
          unattended_dv: false,
          revoke_note: "Revoke from the DigiCert console.",
          unattended_dv_note: "Complete DCV in the DigiCert console.",
        },
      ],
      revoke_capable_count: 1,
      unattended_dv_capable_count: 1,
      guidance: "",
    });
    apiMock.caDiscoveryInventory.mockReset().mockResolvedValue({
      items: [
        {
          id: "external-ca/digicert-prod",
          source_id: "digicert-prod",
          source: "external_ca_registry",
          scope: "public",
          type: "digicert",
          name: "digicert-prod",
          status: "available",
          managed: false,
          inventory_path: "/api/v1/external-cas",
          issuance_path: "/api/v1/external-cas/digicert-prod/issue",
          discovery_methods: ["configured-upstream-ca", "direct-provider-api"],
        },
        {
          id: "external-ca/corp-adcs",
          source_id: "corp-adcs",
          source: "external_ca_registry",
          scope: "private",
          type: "adcs",
          name: "corp-adcs",
          status: "available",
          managed: false,
          inventory_path: "/api/v1/external-cas",
          issuance_path: "/api/v1/external-cas/corp-adcs/issue",
          discovery_methods: ["configured-upstream-ca", "direct-provider-api"],
        },
        {
          id: "ca-authority/ca-existing-imported",
          source_id: "ca-existing-imported",
          source: "ca_hierarchy",
          scope: "private",
          type: "intermediate",
          name: "Imported Existing CA",
          status: "active",
          managed: true,
          serial: "03",
          inventory_path: "/api/v1/ca/authorities",
          issuance_path: "/api/v1/ca/authorities/ca-existing-imported/issue",
          import_path: "/api/v1/ca/authorities/imported",
          discovery_methods: ["public-chain-inspection", "ca-hierarchy-projection", "signer-backed-authority"],
        },
        {
          id: "ca-authority/ca-existing-successor",
          source_id: "ca-existing-successor",
          source: "ca_hierarchy",
          scope: "private",
          type: "intermediate",
          name: "Imported Existing CA v2",
          status: "active",
          managed: true,
          serial: "04",
          inventory_path: "/api/v1/ca/authorities",
          issuance_path: "/api/v1/ca/authorities/ca-existing-successor/issue",
          import_path: "/api/v1/ca/authorities/imported",
          discovery_methods: ["public-chain-inspection", "ca-hierarchy-projection", "signer-backed-authority"],
        },
      ],
      summary: {
        public_count: 1,
        private_count: 3,
        external_registry_count: 2,
        authority_count: 2,
      },
    });
    apiMock.previewCACeremony.mockImplementation(async (input: { operation: string; threshold: number; spec: Record<string, unknown> }) => ({
      capability: "F48",
      operation: input.operation,
      ready: true,
      request_fingerprint: `review-${input.operation}`,
      approval_threshold: input.threshold,
      required_permission: "issuers:write",
      normalized_spec: input.spec,
      changes: ["Prepare the reviewed CA trust change without creating a ceremony or key."],
      risks: ["A completed ceremony can authorize a later trust or signing-authority change."],
      verification_steps: ["Verify distinct approvals and the immutable ceremony event before execution."],
      sensitive_inputs: input.operation === "import_existing_ca" ? ["certificate_pem", "signer_handle"] : [],
      preview_writes: [],
      preview_external_effects: [],
    }));
    apiMock.previewCAAuthorityRotation.mockImplementation(async (predecessorID: string, input: { successor_id: string; reason?: string }) => ({
      capability: "F48",
      operation: "rotate_ca",
      ready: true,
      request_fingerprint: "rotation-review-fingerprint",
      required_permission: "issuers:write",
      reason: input.reason ?? "",
      predecessor: { id: predecessorID, common_name: "Imported Existing CA", kind: "intermediate", status: "active" },
      successor: { id: input.successor_id, common_name: "Imported Existing CA v2", kind: "intermediate", status: "active" },
      changes: ["Route the stable issue URL to the reviewed successor CA."],
      risks: ["Clients must trust the successor chain."],
      verification_steps: ["Issue a test certificate through the stable URL."],
      preview_writes: [],
      preview_external_effects: [],
    }));
    apiMock.createCACeremony.mockImplementation(async (input: { operation: string }) => {
      const base = {
        tenant_id: "tenant-1",
        threshold: 2,
        status: "pending",
        approvals: 1,
        opener: "ra@example.test",
        created_at: "2026-06-26T14:00:00Z",
      };
      if (input.operation === "import_offline_root") {
        return { ...base, id: "ceremony-offline-root", purpose: "offline-root:root-cert-sha" };
      }
      if (input.operation === "create_offline_intermediate") {
        return { ...base, id: "ceremony-offline-intermediate", purpose: "offline-intermediate:ca-offline-root" };
      }
      if (input.operation === "import_existing_ca") {
        return { ...base, id: "ceremony-existing-ca", purpose: "import-existing-ca:customer-existing-ca" };
      }
      if (input.operation === "rekey_ca") {
        return { ...base, id: "ceremony-rekey-ca", purpose: "rotation:ca-existing-imported" };
      }
      return { ...base, id: "ceremony-root-1", purpose: "create_root:Trust Root CA" };
    });
    apiMock.approveCACeremony.mockResolvedValue({
      id: "ceremony-root-1",
      tenant_id: "tenant-1",
      purpose: "create_root:Trust Root CA",
      threshold: 2,
      status: "approved",
      approvals: 2,
      opener: "ra@example.test",
      created_at: "2026-06-26T14:00:00Z",
    });
    apiMock.generateManagedKey.mockResolvedValue({ key_id: "kms/root-1", algorithm: "ECDSA-P256", version: 1, state: "active", public_der: "BASE64PUBLICDER" });
    apiMock.managedKeyCustody.mockResolvedValue({
      enabled: true,
      lifecycle_attached: true,
      ready: true,
      configured_provider: "gcp-kms",
      configuration_mode: "startup_static",
      secret_delivery: "file_reference_only",
      restart_required: false,
      security_boundary: "Private keys stay in the selected provider. Provider credentials are file references read only by the isolated signer.",
      blockers: [],
      providers: [
        { id: "aws", label: "AWS KMS", custody: "AWS keeps the private key.", requirements: [{ key: "region", label: "AWS region", kind: "value", required: true, environment_variable: "TRSTCTL_MANAGED_KEYS_AWS_REGION", description: "Region containing the key." }] },
        { id: "azure-key-vault", label: "Azure Key Vault / Managed HSM", custody: "Azure keeps the private key.", requirements: [{ key: "vault_url", label: "Vault URL", kind: "value", required: true, environment_variable: "TRSTCTL_MANAGED_KEYS_AZURE_VAULT_URL", description: "Approved vault URL." }] },
        { id: "gcp-kms", label: "Google Cloud KMS", custody: "Google keeps the private key.", requirements: [{ key: "parent", label: "Key ring resource", kind: "value", required: true, environment_variable: "TRSTCTL_MANAGED_KEYS_GCP_PARENT", description: "Full key ring parent." }] },
        { id: "pkcs11", label: "PKCS#11 HSM", custody: "The HSM keeps the private key.", requirements: [{ key: "module_path", label: "PKCS#11 module", kind: "value", required: true, environment_variable: "TRSTCTL_MANAGED_KEYS_PKCS11_MODULE_PATH", description: "Signer-only module path." }] },
        { id: "tpm2", label: "TPM 2.0", custody: "The TPM keeps the private key.", requirements: [{ key: "path", label: "TPM device or socket", kind: "value", required: true, environment_variable: "TRSTCTL_MANAGED_KEYS_TPM2_PATH", description: "TPM resource path." }] },
        { id: "yubihsm2", label: "YubiHSM 2", custody: "YubiHSM keeps the private key.", requirements: [{ key: "user_pin_file", label: "Authentication file", kind: "secret_file", required: true, environment_variable: "TRSTCTL_MANAGED_KEYS_YUBIHSM2_USER_PIN_FILE", description: "Signer-only mode-0600 file." }] },
      ],
    });
    apiMock.previewManagedKeyGeneration.mockResolvedValue({
      ready: true,
      effect_free: true,
      provider: "gcp-kms",
      provider_label: "Google Cloud KMS",
      algorithm: "ECDSA-P256",
      configuration_mode: "startup_static",
      restart_required: false,
      extractable: false,
      private_key_location: "Google Cloud KMS",
      required_permission: "keys:write",
      approval_required: false,
      requirements: [{ key: "parent", label: "Key ring resource", kind: "value", required: true, environment_variable: "TRSTCTL_MANAGED_KEYS_GCP_PARENT", description: "Full key ring parent." }],
      preview_writes: [],
      preview_external_effects: [],
      execution_writes: ["One tenant-scoped byok.key.generated event and its managed-key projection."],
      execution_external_effects: ["One durable managedkey.command outbox intent to the isolated signer and selected custody provider."],
      proof: ["Provider key handle", "public-key fingerprint", "non-extractable state", "immutable audit event"],
      blockers: [],
    });
    apiMock.rotateManagedKey.mockResolvedValue({ key_id: "kms/root-1", algorithm: "ECDSA-P256", version: 2, state: "active", public_der: "ROTATEDDER" });
    apiMock.revokeManagedKey.mockResolvedValue({ key_id: "kms/root-1", algorithm: "ECDSA-P256", version: 2, state: "revoked", public_der: "ROTATEDDER" });
    apiMock.zeroizeManagedKey.mockResolvedValue({ key_id: "kms/root-1", algorithm: "ECDSA-P256", version: 2, state: "zeroized" });
    apiMock.issueExternalCA.mockResolvedValue({
      certificate_pem: "-----BEGIN CERTIFICATE-----\nISSUED\n-----END CERTIFICATE-----",
      issuer: "digicert-prod",
      not_after: "2026-07-03T14:00:00Z",
      serial: "ext-ca-serial-001",
    });
    apiMock.importOfflineRootCA.mockResolvedValue({
      id: "ca-offline-root",
      tenant_id: "tenant-1",
      kind: "root",
      common_name: "Offline Root CA",
      signer_handle: "",
      certificate_pem: "-----BEGIN CERTIFICATE-----\nROOT\n-----END CERTIFICATE-----",
      serial: "01",
      max_path_len: 1,
      status: "active",
      created_at: "2026-06-26T14:00:00Z",
    });
    apiMock.createOfflineIntermediateCSR.mockResolvedValue({
      parent_id: "ca-offline-root",
      ceremony_id: "ceremony-offline-intermediate",
      signer_handle: "ca/offline-intermediate/ceremony-offline-intermediate",
      csr_pem: "-----BEGIN CERTIFICATE REQUEST-----\nCSR\n-----END CERTIFICATE REQUEST-----",
    });
    apiMock.importOfflineIntermediateCA.mockResolvedValue({
      id: "ca-offline-intermediate",
      tenant_id: "tenant-1",
      parent_id: "ca-offline-root",
      kind: "intermediate",
      common_name: "Offline Issuing Intermediate",
      signer_handle: "ca/offline-intermediate/ceremony-offline-intermediate",
      certificate_pem: "-----BEGIN CERTIFICATE-----\nINTERMEDIATE\n-----END CERTIFICATE-----",
      serial: "02",
      max_path_len: 0,
      status: "active",
      created_at: "2026-06-26T14:00:00Z",
    });
    apiMock.importExistingCA.mockResolvedValue({
      id: "ca-existing-imported",
      tenant_id: "tenant-1",
      kind: "intermediate",
      common_name: "Imported Existing CA",
      signer_handle: "customer-existing-ca",
      certificate_pem: "-----BEGIN CERTIFICATE-----\nINTERMEDIATE\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nROOT\n-----END CERTIFICATE-----",
      serial: "03",
      max_path_len: 0,
      status: "active",
      created_at: "2026-06-26T14:00:00Z",
    });
    apiMock.rotateCAAuthority.mockResolvedValue({
      predecessor: {
        id: "ca-existing-imported",
        tenant_id: "tenant-1",
        kind: "intermediate",
        common_name: "Imported Existing CA",
        signer_handle: "customer-existing-ca",
        certificate_pem: "-----BEGIN CERTIFICATE-----\nINTERMEDIATE\n-----END CERTIFICATE-----",
        serial: "03",
        max_path_len: 0,
        status: "superseded",
        created_at: "2026-06-26T14:00:00Z",
      },
      successor: {
        id: "ca-existing-successor",
        tenant_id: "tenant-1",
        kind: "intermediate",
        common_name: "Imported Existing CA v2",
        signer_handle: "customer-existing-ca-v2",
        certificate_pem: "-----BEGIN CERTIFICATE-----\nINTERMEDIATE2\n-----END CERTIFICATE-----",
        serial: "04",
        max_path_len: 0,
        status: "active",
        replaces_id: "ca-existing-imported",
        created_at: "2026-06-26T14:00:00Z",
      },
      issue_path: "/api/v1/ca/authorities/ca-existing-imported/issue",
      active_issue_path: "/api/v1/ca/authorities/ca-existing-successor/issue",
      overlap_issuers: [
        { authority_id: "ca-existing-imported", role: "predecessor", status: "superseded", issue_path: "/api/v1/ca/authorities/ca-existing-imported/issue" },
        { authority_id: "ca-existing-successor", role: "successor", status: "active", issue_path: "/api/v1/ca/authorities/ca-existing-successor/issue" },
      ],
    });
    apiMock.rekeyCAAuthority.mockResolvedValue({
      predecessor: {
        id: "ca-existing-imported",
        tenant_id: "tenant-1",
        kind: "intermediate",
        common_name: "Imported Existing CA",
        signer_handle: "customer-existing-ca",
        certificate_pem: "-----BEGIN CERTIFICATE-----\nINTERMEDIATE\n-----END CERTIFICATE-----",
        serial: "03",
        max_path_len: 0,
        status: "superseded",
        created_at: "2026-06-26T14:00:00Z",
      },
      successor: {
        id: "ca-existing-rekeyed",
        tenant_id: "tenant-1",
        kind: "intermediate",
        common_name: "Imported Existing CA",
        signer_handle: "ca-hierarchy-ceremony-rekey-ca",
        certificate_pem: "-----BEGIN CERTIFICATE-----\nREKEYED\n-----END CERTIFICATE-----",
        serial: "05",
        max_path_len: 0,
        status: "active",
        replaces_id: "ca-existing-imported",
        created_at: "2026-06-26T14:05:00Z",
      },
      issue_path: "/api/v1/ca/authorities/ca-existing-imported/issue",
      active_issue_path: "/api/v1/ca/authorities/ca-existing-rekeyed/issue",
      overlap_issuers: [
        { authority_id: "ca-existing-imported", role: "predecessor", status: "superseded", issue_path: "/api/v1/ca/authorities/ca-existing-imported/issue" },
        { authority_id: "ca-existing-rekeyed", role: "successor", status: "active", issue_path: "/api/v1/ca/authorities/ca-existing-rekeyed/issue" },
      ],
    });
  });

  it("opens on an overview-first workspace and deep-links every rare workflow", async () => {
    const user = userEvent.setup();
    renderCAHierarchy();

    expect(await screen.findByRole("tab", { name: "Overview" })).toHaveAttribute("aria-selected", "true");
    const overview = screen.getByRole("region", { name: "CA authority overview" });
    expect(within(overview).getByRole("heading", { name: "Managed authorities" })).toBeInTheDocument();
    expect(within(overview).getByText("Lineage")).toBeInTheDocument();
    expect(within(overview).getByText("Key custody")).toBeInTheDocument();
    expect(within(overview).getByText("Pending actions")).toBeInTheDocument();
    expect(within(overview).queryAllByRole("article")).toHaveLength(0);
    expect(document.getElementById("ca-panel-overview")).not.toHaveClass("hidden");
    expect(document.getElementById("ca-panel-imports")).toHaveClass("hidden");

    await user.click(screen.getByRole("tab", { name: "Imports" }));
    expect(screen.getByRole("tab", { name: "Imports" })).toHaveAttribute("aria-selected", "true");
    expect(document.getElementById("ca-panel-overview")).toHaveClass("hidden");
    expect(document.getElementById("ca-panel-imports")).not.toHaveClass("hidden");

    renderCAHierarchy("/ca-hierarchy?tab=custody");
    expect(screen.getAllByRole("tab", { name: "Key custody" })[1]).toHaveAttribute("aria-selected", "true");
  });

  it("renders issuers with kind, chain, public key, and certificate links", async () => {
    const user = userEvent.setup();
    renderCAHierarchy();

    await user.click(await screen.findByText("Issuance counts and certificate rules"));
    expect(await screen.findByRole("heading", { name: "Certificate authorities" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Issuer visibility" })).toBeInTheDocument();
    expect((await screen.findAllByText("Root CA")).length).toBeGreaterThan(0);
    expect(screen.getByText("x509_ca")).toBeInTheDocument();
    expect(screen.getByText("ssh_ca")).toBeInTheDocument();
    expect(screen.getByText("Root CA -> SSH CA")).toBeInTheDocument();
    expect(screen.getByText(/BEGIN PUBLIC KEY/)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Certificates for Root CA" })).toHaveAttribute("href", "/certificates?issuer=iss-root");
  });

  it("renders public and private direct CA discovery inventory", async () => {
    const user = userEvent.setup();
    renderCAHierarchy();

    await user.click(await screen.findByText("Other discovered certificate authorities"));
    expect(await screen.findByRole("heading", { name: "CA discovery inventory" })).toBeInTheDocument();
    expect(apiMock.caDiscoveryInventory).toHaveBeenCalled();
    expect(screen.getAllByText("digicert-prod").length).toBeGreaterThan(0);
    expect(screen.getAllByText("corp-adcs").length).toBeGreaterThan(0);
    expect(screen.getByText("Imported Existing CA")).toBeInTheDocument();
    expect(screen.getAllByText("External CA registry").length).toBeGreaterThan(0);
    expect(screen.getAllByText("CA hierarchy").length).toBeGreaterThan(0);
    expect(screen.getByText("/api/v1/external-cas/digicert-prod/issue")).toBeInTheDocument();
    expect(screen.getByText("/api/v1/ca/authorities/ca-existing-imported/issue")).toBeInTheDocument();
    expect(screen.queryByText(/BEGIN CERTIFICATE/)).not.toBeInTheDocument();
    expect(screen.queryByText(/PRIVATE KEY/)).not.toBeInTheDocument();
  });

  it("issues through the external CA registry and renders outbox-pending plus issued states", async () => {
    const user = userEvent.setup();
    let resolveIssue: (value: { certificate_pem: string; issuer: string; not_after: string; serial: string }) => void = () => undefined;
    apiMock.issueExternalCA.mockReturnValueOnce(
      new Promise((resolve) => {
        resolveIssue = resolve;
      }),
    );
    renderCAHierarchy();

    const issueRegion = await screen.findByRole("region", { name: "Outbound external CA issuance" });
    await user.selectOptions(within(issueRegion).getByLabelText("External CA"), "digicert-prod");
    await user.clear(within(issueRegion).getByLabelText("Certificate common name"));
    await user.type(within(issueRegion).getByLabelText("Certificate common name"), "svc.digicert.example.com");
    await user.clear(within(issueRegion).getByLabelText("DNS names"));
    await user.type(within(issueRegion).getByLabelText("DNS names"), "svc.digicert.example.com, alt.example.com");
    await user.type(within(issueRegion).getByLabelText("Profile name"), "web-server");
    await user.clear(within(issueRegion).getByLabelText("TTL days"));
    await user.type(within(issueRegion).getByLabelText("TTL days"), "7");
    await user.type(within(issueRegion).getByLabelText("CSR PEM"), "-----BEGIN CERTIFICATE REQUEST-----\nMIIBexampleCSR\n-----END CERTIFICATE REQUEST-----");

    await user.click(within(issueRegion).getByRole("button", { name: "Issue through external CA" }));

    expect(await screen.findByText("outbox-pending")).toBeInTheDocument();
    expect(apiMock.issueExternalCA).toHaveBeenCalledWith("digicert-prod", {
      csr_pem: "-----BEGIN CERTIFICATE REQUEST-----\nMIIBexampleCSR\n-----END CERTIFICATE REQUEST-----",
      dns_names: ["svc.digicert.example.com", "alt.example.com"],
      profile_name: "web-server",
      ttl_seconds: 604800,
    });

    resolveIssue({
      certificate_pem: "-----BEGIN CERTIFICATE-----\nISSUED\n-----END CERTIFICATE-----",
      issuer: "digicert-prod",
      not_after: "2026-07-09T14:00:00Z",
      serial: "ext-ca-serial-001",
    });

    expect(await screen.findByText("external-ca-issued")).toBeInTheDocument();
    expect(screen.getByText("ext-ca-serial-001")).toBeInTheDocument();
    expect(screen.getAllByText("digicert-prod").length).toBeGreaterThan(0);
    expect(screen.queryByText("ISSUED")).not.toBeInTheDocument();
    expect(screen.queryByText(/PRIVATE KEY/)).not.toBeInTheDocument();
  });

  it("activates CA rotation from the discovered signer-backed authorities", async () => {
    const user = userEvent.setup();
    renderCAHierarchy();

    await screen.findByRole("heading", { name: "CA rotation" });
    await user.selectOptions(screen.getByLabelText("Predecessor CA"), "ca-existing-imported");
    await user.selectOptions(screen.getByLabelText("Successor CA"), "ca-existing-successor");
    await user.clear(screen.getByLabelText("Rotation reason"));
    await user.type(screen.getByLabelText("Rotation reason"), "planned overlap");
    await user.click(screen.getByRole("button", { name: "Activate CA rotation" }));

    await waitFor(() =>
      expect(apiMock.previewCAAuthorityRotation).toHaveBeenCalledWith("ca-existing-imported", {
        successor_id: "ca-existing-successor",
        reason: "planned overlap",
      }),
    );
    expect(apiMock.rotateCAAuthority).not.toHaveBeenCalled();
    expect(await screen.findByRole("heading", { name: "Review CA rotation" })).toBeInTheDocument();
    expect(screen.getByText("Imported Existing CA · active")).toBeInTheDocument();
    expect(screen.getByText("Imported Existing CA v2 · active")).toBeInTheDocument();
    expect(screen.getByTitle("rotation-review-fingerprint")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Activate reviewed rotation" }));

    await waitFor(() =>
      expect(apiMock.rotateCAAuthority).toHaveBeenCalledWith("ca-existing-imported", {
        successor_id: "ca-existing-successor",
        reason: "planned overlap",
      }),
    );
    expect(await screen.findByText("Imported Existing CA (superseded)")).toBeInTheDocument();
    expect(screen.getAllByText("Imported Existing CA v2 (active)").length).toBeGreaterThan(0);
    expect(screen.getAllByText("/api/v1/ca/authorities/ca-existing-imported/issue").length).toBeGreaterThan(0);
    expect(screen.getAllByText("/api/v1/ca/authorities/ca-existing-successor/issue").length).toBeGreaterThan(0);
  });

  it("starts a CA re-key ceremony and activates fresh CA material", async () => {
    const user = userEvent.setup();
    renderCAHierarchy();

    await screen.findByRole("heading", { name: "CA renewal and re-key" });
    await user.selectOptions(screen.getByLabelText("CA authority"), "ca-existing-imported");
    await user.click(screen.getByRole("button", { name: "Start re-key ceremony" }));
    await user.click(within(await screen.findByRole("dialog", { name: "Review CA ceremony" })).getByRole("button", { name: "Start reviewed ceremony" }));

    await waitFor(() =>
      expect(apiMock.createCACeremony).toHaveBeenCalledWith({
        operation: "rekey_ca",
        authority_id: "ca-existing-imported",
        threshold: 2,
        spec: { common_name: "Imported Existing CA" },
      }),
    );
    expect(await screen.findByDisplayValue("ceremony-rekey-ca")).toBeInTheDocument();

    await user.clear(screen.getByLabelText("Validity days"));
    await user.type(screen.getByLabelText("Validity days"), "90");
    await user.clear(screen.getByLabelText("Re-key reason"));
    await user.type(screen.getByLabelText("Re-key reason"), "planned renewal");
    await user.click(screen.getByRole("button", { name: "Re-key CA" }));

    await waitFor(() =>
      expect(apiMock.rekeyCAAuthority).toHaveBeenCalledWith("ca-existing-imported", {
        ceremony_id: "ceremony-rekey-ca",
        ttl_seconds: 7_776_000,
        reason: "planned renewal",
      }),
    );
    expect(await screen.findByText("Fresh successor")).toBeInTheDocument();
    expect(screen.getAllByText("/api/v1/ca/authorities/ca-existing-imported/issue").length).toBeGreaterThan(0);
    expect(screen.getAllByText("/api/v1/ca/authorities/ca-existing-rekeyed/issue").length).toBeGreaterThan(0);
  }, 10000);

  it("starts and approves a CA key ceremony through the API", async () => {
    const user = userEvent.setup();
    renderCAHierarchy();

    await user.click(await screen.findByRole("button", { name: "Start root ceremony" }));

    await waitFor(() =>
      expect(apiMock.previewCACeremony).toHaveBeenCalledWith({
        operation: "create_root",
        threshold: 2,
        spec: expect.objectContaining({ common_name: "Trust Root CA", signature_algorithm: "ECDSA-P256" }),
      }),
    );
    expect(apiMock.createCACeremony).not.toHaveBeenCalled();
    const review = await screen.findByRole("dialog", { name: "Review CA ceremony" });
    expect(within(review).getByText("No ceremony, key, certificate, or external request has been created.")).toBeInTheDocument();
    expect(within(review).getByText("2 distinct approvals")).toBeInTheDocument();
    expect(within(review).getByText("review-create_root")).toBeInTheDocument();

    await user.click(within(review).getByRole("button", { name: "Start reviewed ceremony" }));

    await waitFor(() =>
      expect(apiMock.createCACeremony).toHaveBeenCalledWith({
        operation: "create_root",
        threshold: 2,
        spec: expect.objectContaining({ common_name: "Trust Root CA", signature_algorithm: "ECDSA-P256" }),
      }),
    );
    expect(await screen.findByText("ceremony-root-1")).toBeInTheDocument();
    expect(screen.getByText("1 / 2 approvals")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Approve ceremony ceremony-root-1" }));

    await waitFor(() => expect(apiMock.approveCACeremony).toHaveBeenCalledWith("ceremony-root-1"));
    expect(await screen.findByText("2 / 2 approvals")).toBeInTheDocument();
    expect(screen.getByText("approved")).toBeInTheDocument();
    expect(screen.queryByText("root:<sha256-of-ca-spec>")).not.toBeInTheDocument();
  });

  it("configures, previews, then generates managed-key custody without private key bytes", async () => {
    const user = userEvent.setup();
    renderCAHierarchy("/ca-hierarchy?tab=custody");

    expect(await screen.findByRole("heading", { name: "Managed key custody" })).toBeInTheDocument();
    const provider = await screen.findByRole("combobox", { name: "Custody provider" });
    expect(within(provider).getAllByRole("option")).toHaveLength(6);
    expect(screen.getByText("Configured now: Google Cloud KMS")).toBeInTheDocument();
    expect(screen.getByText("Key ring resource")).toBeInTheDocument();
    expect(screen.getByText("TRSTCTL_MANAGED_KEYS_GCP_PARENT")).toBeInTheDocument();
    expect(apiMock.generateManagedKey).not.toHaveBeenCalled();

    await user.click(screen.getByRole("button", { name: "Review generation plan" }));
    await waitFor(() => expect(apiMock.previewManagedKeyGeneration).toHaveBeenCalledWith({ provider: "gcp-kms", algorithm: "ECDSA-P256" }));
    expect(await screen.findByRole("heading", { name: "Nothing changed yet" })).toBeInTheDocument();
    expect(screen.getByText("0 preview writes · 0 outside calls")).toBeInTheDocument();
    expect(screen.getByText("One tenant-scoped byok.key.generated event and its managed-key projection.")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Continue to generation" }));
    await user.click(screen.getByRole("button", { name: "Generate managed key" }));

    await waitFor(() => expect(apiMock.generateManagedKey).toHaveBeenCalledWith({ algorithm: "ECDSA-P256" }));
    expect(await screen.findByText("kms/root-1")).toBeInTheDocument();
    expect(screen.getByText("Version 1")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Rotate key kms/root-1" }));
    await waitFor(() => expect(apiMock.rotateManagedKey).toHaveBeenCalledWith("kms/root-1"));
    expect(await screen.findByText("Version 2")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Revoke key kms/root-1" }));
    await waitFor(() => expect(apiMock.revokeManagedKey).toHaveBeenCalledWith("kms/root-1"));
    expect(await screen.findByText("revoked")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Zeroize key kms/root-1" }));
    await waitFor(() => expect(apiMock.zeroizeManagedKey).toHaveBeenCalledWith("kms/root-1"));
    expect(await screen.findByText("zeroized")).toBeInTheDocument();
    expect(screen.queryByText(/BEGIN PRIVATE KEY/)).not.toBeInTheDocument();
    expect(screen.queryByText(/PRIVATE KEY-----/)).not.toBeInTheDocument();
  });

  it("keeps generation locked when the server preview names a deployment blocker", async () => {
    const user = userEvent.setup();
    apiMock.managedKeyCustody.mockResolvedValueOnce({
      ...(await apiMock.managedKeyCustody()),
      enabled: false,
      lifecycle_attached: false,
      ready: false,
      configured_provider: "",
      restart_required: true,
      blockers: ["Managed-key custody is disabled. Enable it and restart the control plane and isolated signer."],
    });
    apiMock.previewManagedKeyGeneration.mockResolvedValueOnce({
      ...(await apiMock.previewManagedKeyGeneration()),
      ready: false,
      restart_required: true,
      blockers: ["Managed-key custody is disabled. Apply the startup configuration and restart."],
    });
    renderCAHierarchy("/ca-hierarchy?tab=custody");

    await user.click(await screen.findByRole("button", { name: "Review generation plan" }));
    expect(await screen.findByText("Managed-key custody is disabled. Apply the startup configuration and restart.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Continue to generation" })).toBeDisabled();
    expect(screen.queryByRole("button", { name: "Generate managed key" })).not.toBeInTheDocument();
  });

  it("drives the offline-root import and offline-signed intermediate workflow", async () => {
    const user = userEvent.setup();
    renderCAHierarchy();

    const rootPEM = "-----BEGIN CERTIFICATE-----\nROOT\n-----END CERTIFICATE-----";
    await user.type(await screen.findByLabelText("Offline root certificate PEM"), rootPEM);
    await user.click(screen.getByRole("button", { name: "Start offline-root ceremony" }));
    await user.click(within(await screen.findByRole("dialog", { name: "Review CA ceremony" })).getByRole("button", { name: "Start reviewed ceremony" }));

    await waitFor(() =>
      expect(apiMock.createCACeremony).toHaveBeenCalledWith({
        operation: "import_offline_root",
        threshold: 2,
        certificate_pem: rootPEM,
        spec: expect.objectContaining({ common_name: "Offline Root CA", max_path_len: 1, signature_algorithm: "ECDSA-P256" }),
      }),
    );
    expect(await screen.findByDisplayValue("ceremony-offline-root")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Import offline root" }));
    await waitFor(() =>
      expect(apiMock.importOfflineRootCA).toHaveBeenCalledWith(expect.objectContaining({ ceremony_id: "ceremony-offline-root", certificate_pem: rootPEM })),
    );
    expect(await screen.findByText("ca-offline-root")).toBeInTheDocument();
    expect(screen.getByDisplayValue("ca-offline-root")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Start intermediate ceremony" }));
    await user.click(within(await screen.findByRole("dialog", { name: "Review CA ceremony" })).getByRole("button", { name: "Start reviewed ceremony" }));
    await waitFor(() =>
      expect(apiMock.createCACeremony).toHaveBeenCalledWith({
        operation: "create_offline_intermediate",
        threshold: 2,
        parent_id: "ca-offline-root",
        spec: expect.objectContaining({ common_name: "Offline Issuing Intermediate", max_path_len: 0 }),
      }),
    );
    expect(await screen.findByDisplayValue("ceremony-offline-intermediate")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Generate signer CSR" }));
    await waitFor(() =>
      expect(apiMock.createOfflineIntermediateCSR).toHaveBeenCalledWith(
        "ca-offline-root",
        expect.objectContaining({
          ceremony_id: "ceremony-offline-intermediate",
          spec: expect.objectContaining({ common_name: "Offline Issuing Intermediate" }),
        }),
      ),
    );
    const csrTextArea = (await screen.findByLabelText("Signer CSR PEM")) as HTMLTextAreaElement;
    expect(csrTextArea.value).toContain("BEGIN CERTIFICATE REQUEST");

    const intermediatePEM = "-----BEGIN CERTIFICATE-----\nINTERMEDIATE\n-----END CERTIFICATE-----";
    await user.type(screen.getByLabelText("Offline-signed intermediate PEM"), intermediatePEM);
    await user.click(screen.getByRole("button", { name: "Import offline-signed intermediate" }));
    await waitFor(() =>
      expect(apiMock.importOfflineIntermediateCA).toHaveBeenCalledWith(
        "ca-offline-root",
        expect.objectContaining({ ceremony_id: "ceremony-offline-intermediate", certificate_pem: intermediatePEM }),
      ),
    );
    expect(await screen.findByText("ca-offline-intermediate")).toBeInTheDocument();
    expect(screen.queryByText(/BEGIN PRIVATE KEY/)).not.toBeInTheDocument();
  });

  it("imports an existing signer-backed CA chain without collecting private key bytes", async () => {
    const user = userEvent.setup();
    renderCAHierarchy();

    const chainPEM = "-----BEGIN CERTIFICATE-----\nINTERMEDIATE\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nROOT\n-----END CERTIFICATE-----";
    await user.clear(await screen.findByLabelText("Signer handle"));
    await user.type(screen.getByLabelText("Signer handle"), "customer-existing-ca");
    await user.type(screen.getByLabelText("Existing CA chain PEM"), chainPEM);
    await user.click(screen.getByRole("button", { name: "Start existing-CA ceremony" }));
    await user.click(within(await screen.findByRole("dialog", { name: "Review CA ceremony" })).getByRole("button", { name: "Start reviewed ceremony" }));

    await waitFor(() =>
      expect(apiMock.createCACeremony).toHaveBeenCalledWith({
        operation: "import_existing_ca",
        threshold: 2,
        certificate_pem: chainPEM,
        signer_handle: "customer-existing-ca",
        spec: expect.objectContaining({ common_name: "Imported Existing CA", max_path_len: 0, signature_algorithm: "ECDSA-P256" }),
      }),
    );
    expect(await screen.findByDisplayValue("ceremony-existing-ca")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Import existing CA" }));
    await waitFor(() =>
      expect(apiMock.importExistingCA).toHaveBeenCalledWith(
        expect.objectContaining({
          ceremony_id: "ceremony-existing-ca",
          certificate_pem: chainPEM,
          signer_handle: "customer-existing-ca",
        }),
      ),
    );
    await waitFor(() => expect(screen.getAllByText("ca-existing-imported").length).toBeGreaterThan(0));
    expect(screen.getAllByText("customer-existing-ca").length).toBeGreaterThan(0);
    expect(screen.queryByLabelText(/private key/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/BEGIN PRIVATE KEY/)).not.toBeInTheDocument();
  });

  it("surfaces issuer permission errors without hiding ceremony and custody actions", async () => {
    const user = userEvent.setup();
    apiMock.issuers.mockRejectedValueOnce(new ApiError(403, JSON.stringify({ detail: "missing issuers:read" })));
    renderCAHierarchy();

    expect(await screen.findByText("Permission denied")).toBeInTheDocument();
    expect(screen.getByText("missing issuers:read")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Start root ceremony" })).toBeInTheDocument();
    await user.click(screen.getByRole("tab", { name: "Key custody" }));
    expect(await screen.findByRole("button", { name: "Review generation plan" })).toBeInTheDocument();
  });

  it("traps focus in the issuer configuration dialog and returns focus to the opener", async () => {
    const user = userEvent.setup();
    renderCAHierarchy();

    const opener = await screen.findByRole("button", { name: "Configure ACME" });
    await user.click(opener);

    const dialog = await screen.findByRole("dialog", { name: "Configure ACME issuer" });
    const issuerName = within(dialog).getByLabelText("Issuer name");
    const close = within(dialog).getByRole("button", { name: "Close issuer form" });
    const cancel = within(dialog).getByRole("button", { name: "Cancel" });

    expect(issuerName).toHaveFocus();

    close.focus();
    await user.tab({ shift: true });
    expect(cancel).toHaveFocus();

    await user.tab();
    expect(close).toHaveFocus();

    await user.keyboard("{Escape}");
    expect(screen.queryByRole("dialog", { name: "Configure ACME issuer" })).not.toBeInTheDocument();
    expect(opener).toHaveFocus();
  });
  // The capability columns must resolve the AUTHORITY, not the issuer's
  // key type (epics R2 + B7).
  //
  // This is the test whose absence let a dead column ship. Both capability
  // cells looked their row up with `c.issuer === issuer.kind`, but Issuer.kind
  // is "x509_ca" | "ssh_ca" while the census is keyed by authority kind
  // ("letsencrypt", "digicert"). The two axes never intersect, so every row
  // rendered "Unknown — capability matrix unavailable" — telling the operator
  // the census was broken when the census was fine and the lookup was wrong.
  //
  // The bridge is the external-CA registry, where `type` IS the authority kind.
  it("shows each external issuer's real revocation and domain-validation capability", async () => {
    apiMock.externalCAs.mockResolvedValue([{ id: "iss-ssh", type: "digicert", name: "SSH CA", status: "available" }]);
    renderCAHierarchy();

    // DigiCert: no shipped revocation, no unattended DV — and both notes say
    // where to go instead, which is the whole point of a false row.
    expect(await screen.findByText("Revoke at the authority")).toBeInTheDocument();
    expect(screen.getByText("Revoke from the DigiCert console.")).toBeInTheDocument();
    expect(screen.getByText("Manual step")).toBeInTheDocument();
    expect(screen.getByText("Complete DCV in the DigiCert console.")).toBeInTheDocument();
    // The failure this replaces: the cell used to read "unavailable" for every
    // configured authority.
    expect(screen.queryByText(/capability matrix unavailable/i)).toBeNull();
  });

  // An INTERNAL issuer is a third answer, not a missing one. trstctl is the CA,
  // so revocation runs through its own CRL/OCSP and there is no upstream
  // challenge to automate. Rendering "unknown" there would invite an operator
  // to go looking for a vendor console that does not exist.
  it("says internal authorities have no upstream vendor rather than reading unknown", async () => {
    apiMock.issuers.mockResolvedValue([
      {
        id: "iss-root",
        name: "Root CA",
        kind: "x509_ca",
        internal: true,
        chain: ["Root CA"],
        public_key: "-----BEGIN PUBLIC KEY-----ROOT-----END PUBLIC KEY-----",
      },
    ]);
    renderCAHierarchy();

    expect(await screen.findByText("trstctl issues and revokes this")).toBeInTheDocument();
    expect(screen.getByText("No domain validation")).toBeInTheDocument();
  });

  it("explains when the external CA registry is not enabled", async () => {
    apiMock.externalCAs.mockRejectedValue(
      new ApiError(503, JSON.stringify({ title: "Service Unavailable", status: 503, detail: "external CA registry is not enabled" })),
    );

    renderCAHierarchy();

    expect(await screen.findByText(/External CA registry is not connected/)).toBeInTheDocument();
    expect(screen.getByText("external CA registry is not enabled")).toBeInTheDocument();
    expect(screen.queryByText("External CA registry is unavailable")).not.toBeInTheDocument();
  });

  it("uses runtime capability truth instead of probing an unavailable external CA service", async () => {
    renderCAHierarchy("/ca-hierarchy", externalCAUnavailableRuntime());

    expect(await screen.findByText("No external CA service is configured in this deployment.")).toBeInTheDocument();
    expect(apiMock.externalCAs).not.toHaveBeenCalled();
    expect(apiMock.issuers).toHaveBeenCalledTimes(1);
    expect(apiMock.caAuthorities).toHaveBeenCalledTimes(1);
  });

  it("requires explicit confirmation, requests signer-gated retirement, and downloads the projected record", async () => {
    const user = userEvent.setup();
    apiMock.caAuthorities.mockResolvedValue({
      items: [
        {
          id: "ca-retired",
          tenant_id: "tenant-1",
          common_name: "Retired Root CA",
          kind: "root",
          status: "superseded",
          certificate_pem: "public certificate",
          signer_handle: "signer-handle-retired",
          serial: "42",
          max_path_len: 1,
          created_at: "2026-08-12T00:00:00Z",
        },
      ],
    });
    const signedRecord = JSON.stringify({
      commitment: { tenant_id: "tenant-1", stable_key_id: "ca-retired", final_epoch: 7 },
      signature: "offline-signature",
    });
    apiMock.caRetirementChecklist
      .mockResolvedValueOnce({
        key_id: "ca-retired",
        blocked: true,
        accounted: 1,
        total: 2,
        outstanding: [{ kind: "credential", ref: "leaf-2" }],
        guidance: "The isolated signer owns the final decision.",
      })
      .mockResolvedValueOnce({
        key_id: "ca-retired",
        blocked: false,
        accounted: 2,
        total: 2,
        outstanding: [],
        retirement_status: "destroyed",
        destruction_record: signedRecord,
        guidance: "The key was destroyed inside the isolated signer.",
      });

    renderCAHierarchy("/ca-hierarchy?tab=lifecycle");
    const panel = await screen.findByRole("region", { name: "Key retirement" });
    const retire = within(panel).getByRole("button", { name: "Irreversibly retire key" });
    expect(retire).toBeDisabled();
    await user.clear(within(panel).getByLabelText("Final dependency epoch"));
    await user.type(within(panel).getByLabelText("Final dependency epoch"), "7");
    await user.click(within(panel).getByLabelText("I understand this permanently destroys the signer-held key"));
    await user.click(retire);

    await waitFor(() =>
      expect(apiMock.retireCAKey).toHaveBeenCalledWith("ca-retired", {
        final_epoch: 7,
        confirm_irreversible: true,
      }),
    );
    const download = await within(panel).findByRole("link", { name: "Download offline-verifiable destruction record" });
    expect(download).toHaveAttribute("download", "trstctl-ca-key-ca-retired-destruction-record.json");
    expect(download.getAttribute("href")).toContain(encodeURIComponent("offline-signature"));
    expect(within(panel).getByText("destroyed")).toBeInTheDocument();
  });
});
