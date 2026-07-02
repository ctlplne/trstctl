import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { ApiError } from "@/lib/api";
import { CAHierarchy } from "@/pages/CAHierarchy";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    issuers: vi.fn(),
    profiles: vi.fn(),
    caDiscoveryInventory: vi.fn(),
    externalCAs: vi.fn(),
    createCACeremony: vi.fn(),
    approveCACeremony: vi.fn(),
    importOfflineRootCA: vi.fn(),
    importExistingCA: vi.fn(),
    createOfflineIntermediateCSR: vi.fn(),
    importOfflineIntermediateCA: vi.fn(),
    rotateCAAuthority: vi.fn(),
    rekeyCAAuthority: vi.fn(),
    generateManagedKey: vi.fn(),
    rotateManagedKey: vi.fn(),
    revokeManagedKey: vi.fn(),
    zeroizeManagedKey: vi.fn(),
    issueExternalCA: vi.fn(),
  },
}));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: apiMock };
});

function renderCAHierarchy() {
  return render(
    <MemoryRouter>
      <CAHierarchy />
    </MemoryRouter>,
  );
}

describe("CA hierarchy and custody surface", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    for (const mock of Object.values(apiMock)) mock.mockReset();
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

  it("renders issuers with kind, chain, public key, and certificate links", async () => {
    renderCAHierarchy();

    expect(await screen.findByRole("heading", { name: "CA hierarchy" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Issuer visibility" })).toBeInTheDocument();
    expect((await screen.findAllByText("Root CA")).length).toBeGreaterThan(0);
    expect(screen.getByText("x509_ca")).toBeInTheDocument();
    expect(screen.getByText("ssh_ca")).toBeInTheDocument();
    expect(screen.getByText("Root CA -> SSH CA")).toBeInTheDocument();
    expect(screen.getByText(/BEGIN PUBLIC KEY/)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Certificates for Root CA" })).toHaveAttribute("href", "/certificates?issuer=iss-root");
  });

  it("renders public and private direct CA discovery inventory", async () => {
    renderCAHierarchy();

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
    await user.type(
      within(issueRegion).getByLabelText("CSR PEM"),
      "-----BEGIN CERTIFICATE REQUEST-----\nMIIBexampleCSR\n-----END CERTIFICATE REQUEST-----",
    );

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
  });

  it("starts and approves a CA key ceremony through the API", async () => {
    const user = userEvent.setup();
    renderCAHierarchy();

    await user.click(await screen.findByRole("button", { name: "Start root ceremony" }));

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

  it("generates and acts on managed-key custody metadata without private key bytes", async () => {
    const user = userEvent.setup();
    renderCAHierarchy();

    expect(await screen.findByRole("heading", { name: "Managed key custody" })).toBeInTheDocument();
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

  it("drives the offline-root import and offline-signed intermediate workflow", async () => {
    const user = userEvent.setup();
    renderCAHierarchy();

    const rootPEM = "-----BEGIN CERTIFICATE-----\nROOT\n-----END CERTIFICATE-----";
    await user.type(await screen.findByLabelText("Offline root certificate PEM"), rootPEM);
    await user.click(screen.getByRole("button", { name: "Start offline-root ceremony" }));

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
    await waitFor(() => expect(apiMock.importOfflineRootCA).toHaveBeenCalledWith(expect.objectContaining({ ceremony_id: "ceremony-offline-root", certificate_pem: rootPEM })));
    expect(await screen.findByText("ca-offline-root")).toBeInTheDocument();
    expect(screen.getByDisplayValue("ca-offline-root")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Start intermediate ceremony" }));
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
        expect.objectContaining({ ceremony_id: "ceremony-offline-intermediate", spec: expect.objectContaining({ common_name: "Offline Issuing Intermediate" }) }),
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
    apiMock.issuers.mockRejectedValueOnce(new ApiError(403, JSON.stringify({ detail: "missing issuers:read" })));
    renderCAHierarchy();

    expect(await screen.findByText("Permission denied")).toBeInTheDocument();
    expect(screen.getByText("missing issuers:read")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Start root ceremony" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Generate managed key" })).toBeInTheDocument();
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
});
