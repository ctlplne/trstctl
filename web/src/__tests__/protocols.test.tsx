import { beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { RbacProvider } from "@/components/rbac";
import { ToastProvider } from "@/components/ToastProvider";
import { ApiError, type EnrollmentDiagnosticList } from "@/lib/api";
import { AppQueryProvider } from "@/lib/query";
import { Protocols } from "@/pages/Protocols";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    protocolStatuses: vi.fn(),
    estQualification: vi.fn(),
    scepQualification: vi.fn(),
    cmpQualification: vi.fn(),
    spiffeQualification: vi.fn(),
    acmeOperatorPlan: vi.fn(),
    activateProtocolProfile: vi.fn(),
    acmeARIPosture: vi.fn(),
    acmeDNS01Providers: vi.fn(),
    acmeDNS01ProviderConfigs: vi.fn(),
    mdmSCEPStatus: vi.fn(),
    previewMDMSCEPPolicy: vi.fn(),
    previewMDMSCEPPolicyUpdate: vi.fn(),
    createMDMSCEPPolicy: vi.fn(),
    updateMDMSCEPPolicy: vi.fn(),
    previewMDMSCEPChallengeRotation: vi.fn(),
    rotateMDMSCEPChallenge: vi.fn(),
    deleteMDMSCEPPolicy: vi.fn(),
    createACMEDNS01ProviderConfig: vi.fn(),
    updateACMEDNS01ProviderConfig: vi.fn(),
    deleteACMEDNS01ProviderConfig: vi.fn(),
    acmeDNS01Preflight: vi.fn(),
    previewACMEDNS01Qualification: vi.fn(),
    runACMEDNS01Qualification: vi.fn(),
    acmeDNS01QualificationRuns: vi.fn(),
    retryACMEDNS01QualificationCleanup: vi.fn(),
    acmeUpstreamAuthorizations: vi.fn(),
    enrollmentDiagnostics: vi.fn(),
    proveEnrollmentDiagnosticFixed: vi.fn(),
    agentPage: vi.fn(),
    revocationCaches: vi.fn(),
  },
}));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...apiMock } };
});

function mountProtocols(permissions: readonly string[] | null = null, openOperations = true) {
  const result = render(
    <AppQueryProvider>
      <RbacProvider permissions={permissions}>
        <MemoryRouter>
          <ToastProvider>
            <Protocols />
          </ToastProvider>
        </MemoryRouter>
      </RbacProvider>
    </AppQueryProvider>,
  );
  if (openOperations) fireEvent.click(screen.getByText("Set up and operate methods"));
  return result;
}

async function renderProtocols() {
  const result = mountProtocols();
  await waitFor(() => expect(apiMock.protocolStatuses).toHaveBeenCalledTimes(1));
  await waitFor(() => expect(apiMock.acmeOperatorPlan).toHaveBeenCalledTimes(1));
  await waitFor(() => expect(apiMock.acmeARIPosture).toHaveBeenCalledTimes(1));
  await waitFor(() => expect(apiMock.acmeDNS01Providers).toHaveBeenCalledTimes(1));
  await waitFor(() => expect(apiMock.acmeDNS01ProviderConfigs).toHaveBeenCalledTimes(1));
  await waitFor(() => expect(apiMock.mdmSCEPStatus).toHaveBeenCalledTimes(1));
  await screen.findByText("ACME directory responded.");
  return result;
}

function installClipboardSpy() {
  const writeText = vi.fn().mockResolvedValue(undefined);
  const clipboard = { writeText };
  Object.defineProperty(window.navigator, "clipboard", {
    configurable: true,
    value: clipboard,
  });
  Object.defineProperty(globalThis.navigator, "clipboard", {
    configurable: true,
    value: clipboard,
  });
  return writeText;
}

function readyACMEOperatorPlan() {
  return {
    ready: true,
    served: true,
    tenant_bound: true,
    directory_path: "/directory",
    challenge_methods: ["http-01", "dns-01", "tls-alpn-01"],
    eab_required: true,
    eab_configured: 2,
    eab_active: 1,
    dns01_provider_configs: 1,
    issuing_profile: "service-mtls-30d",
    issuing_profile_ready: true,
    activation_mode: "startup_configuration",
    activation_required: false,
    activation_available: false,
    next_action: {
      kind: "connect_acme_client",
      label: "Connect an ACME client",
      detail: "Point a stock ACME client at this directory.",
      method: "GET",
      path: "/directory",
    },
    blockers: [],
    warnings: ["One EAB credential is disabled; one remains active."],
    recovery_steps: ["Open Enrollment diagnostics after a client refusal, repair the named cause, and retry without weakening validation."],
    preview_writes: [],
    preview_external_effects: [],
    generated_at: "2026-08-27T23:45:00Z",
  };
}

describe("protocol surface", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    apiMock.protocolStatuses.mockReset();
    apiMock.estQualification.mockReset();
    apiMock.scepQualification.mockReset();
    apiMock.cmpQualification.mockReset();
    apiMock.spiffeQualification.mockReset();
    apiMock.acmeOperatorPlan.mockReset();
    apiMock.activateProtocolProfile.mockReset();
    apiMock.acmeARIPosture.mockReset();
    apiMock.acmeDNS01Providers.mockReset();
    apiMock.acmeDNS01ProviderConfigs.mockReset();
    apiMock.mdmSCEPStatus.mockReset();
    apiMock.previewMDMSCEPPolicy.mockReset();
    apiMock.previewMDMSCEPPolicyUpdate.mockReset();
    apiMock.createMDMSCEPPolicy.mockReset();
    apiMock.updateMDMSCEPPolicy.mockReset();
    apiMock.previewMDMSCEPChallengeRotation.mockReset();
    apiMock.rotateMDMSCEPChallenge.mockReset();
    apiMock.deleteMDMSCEPPolicy.mockReset();
    apiMock.createACMEDNS01ProviderConfig.mockReset();
    apiMock.updateACMEDNS01ProviderConfig.mockReset();
    apiMock.deleteACMEDNS01ProviderConfig.mockReset();
    apiMock.acmeDNS01Preflight.mockReset();
    apiMock.previewACMEDNS01Qualification.mockReset();
    apiMock.runACMEDNS01Qualification.mockReset();
    apiMock.acmeDNS01QualificationRuns.mockReset();
    apiMock.retryACMEDNS01QualificationCleanup.mockReset();
    apiMock.acmeUpstreamAuthorizations.mockReset();
    apiMock.enrollmentDiagnostics.mockReset();
    apiMock.proveEnrollmentDiagnosticFixed.mockReset();
    apiMock.agentPage.mockReset();
    apiMock.revocationCaches.mockReset();
    apiMock.acmeOperatorPlan.mockResolvedValue(readyACMEOperatorPlan());
    apiMock.estQualification.mockResolvedValue({
      checked_at: "2026-08-28T12:00:00Z",
      passed: true,
      checks: [
        {
          id: "ca-chain",
          method: "GET",
          endpoint: "/.well-known/est/cacerts",
          expected: "HTTP 200 with a base64 PKCS#7 CA chain",
          status_code: 200,
          passed: true,
          detail: "The CA chain is available and structurally valid.",
        },
        {
          id: "csr-rules",
          method: "GET",
          endpoint: "/.well-known/est/csrattrs",
          expected: "HTTP 204 or a valid CSR-attributes response",
          status_code: 204,
          passed: true,
          detail: "The server advertises no extra CSR attributes.",
        },
        {
          id: "auth-gate",
          method: "POST",
          endpoint: "/.well-known/est/simpleenroll",
          expected: "HTTP 401 with a Bearer authentication challenge",
          status_code: 401,
          passed: true,
          detail: "Enrollment refused the credential-free probe before reading a CSR.",
        },
      ],
    });
    apiMock.scepQualification.mockResolvedValue({
      checked_at: "2026-08-28T12:00:00Z",
      passed: true,
      checks: [
        {
          id: "capabilities",
          method: "GET",
          endpoint: "/scep?operation=GetCACaps",
          expected: "HTTP 200 with POSTPKIOperation, SHA-256, and SCEPStandard",
          status_code: 200,
          passed: true,
          detail: "The responder advertises the required SCEP capabilities.",
        },
        {
          id: "ca-material",
          method: "GET",
          endpoint: "/scep?operation=GetCACert",
          expected: "HTTP 200 with a structurally valid CA certificate or CA/RA bundle",
          status_code: 200,
          passed: true,
          detail: "The public CA or CA/RA material is available and structurally valid.",
        },
        {
          id: "empty-message-gate",
          method: "POST",
          endpoint: "/scep?operation=PKIOperation",
          expected: "HTTP 400 before an empty PKI message can reach enrollment",
          status_code: 400,
          passed: true,
          detail: "Enrollment refused the empty PKI message before reading a CSR or challenge.",
        },
      ],
    });
    apiMock.cmpQualification.mockResolvedValue({
      checked_at: "2026-08-28T12:00:00Z",
      ready: true,
      effect_free: true,
      endpoint: "/cmp",
      profile: "device-90d",
      binding_mode: "subject-bound",
      client_trust_anchor_count: 2,
      checks: [
        { id: "configured", label: "CMP enabled", passed: true, detail: "CMP is enabled in startup configuration." },
        { id: "endpoint-mounted", label: "CMP endpoint mounted", passed: true, detail: "The running control plane owns POST /cmp." },
        { id: "tenant-binding", label: "Tenant binding", passed: true, detail: "The CMP mount is bound to this authenticated tenant." },
        { id: "ra-transport", label: "RA transport identity", passed: true, detail: "The sealed CMP response-protection identity is loaded in memory." },
        {
          id: "client-trust",
          label: "Client protection trust",
          passed: true,
          detail: "At least one operator-approved client protection trust anchor is loaded.",
        },
        { id: "issuing-path", label: "Isolated issuing path", passed: true, detail: "The event-sourced issuer and isolated signer path are attached." },
        { id: "profile-policy", label: "Issuing profile", passed: true, detail: "The server can enforce the device-90d certificate profile." },
        { id: "bounded-capacity", label: "Bounded enrollment capacity", passed: true, detail: "CMP enrollment uses the bounded protocol worker pool." },
      ],
      preview_writes: [],
      preview_external_effects: [],
      preview_signer_calls: [],
      proof: ["In-memory only.", "No request material.", "No effects."],
      blockers: [],
    });
    apiMock.spiffeQualification.mockResolvedValue({
      checked_at: "2026-08-29T12:00:00Z",
      ready: true,
      effect_free: true,
      trust_domain: "workloads.example.test",
      socket_uri: "unix:///run/trstctl-spiffe/workload.sock",
      transport: "unix",
      socket_mode: "Srwx------",
      registration_entry_count: 1,
      local_socket_deprecated: true,
      supported_operations: ["FetchX509SVID", "FetchX509Bundles", "FetchJWTSVID", "FetchJWTBundles", "ValidateJWTSVID"],
      checks: [
        { id: "configured", label: "SPIFFE enabled", passed: true, detail: "SPIFFE is enabled in startup configuration." },
        { id: "workload-api-built", label: "Workload API built", passed: true, detail: "The running control plane assembled the SPIFFE Workload API." },
        { id: "activation", label: "Protocol profile active", passed: true, detail: "The configured protocol profile allows the Workload API to serve." },
        { id: "tenant-binding", label: "Tenant binding", passed: true, detail: "The Workload API is bound to this authenticated tenant." },
        { id: "socket-listening", label: "Unix socket listening", passed: true, detail: "The configured path is a live Unix domain socket." },
        { id: "socket-permissions", label: "Socket owner-only", passed: true, detail: "The socket denies group and other access." },
        {
          id: "registration-policy",
          label: "Registration policy attached",
          passed: true,
          detail: "At least one registration entry can bind an approved workload to a SPIFFE ID.",
        },
        { id: "issuing-path", label: "Isolated issuing path", passed: true, detail: "X.509 and JWT issuance route through the isolated signer boundary." },
        { id: "bounded-capacity", label: "Bounded workload capacity", passed: true, detail: "Workload requests use the bounded protocol worker pool." },
      ],
      preview_writes: [],
      preview_external_effects: [],
      preview_signer_calls: [],
      proof: ["Server posture only.", "No workload call.", "No effects."],
      blockers: [],
      client_boundary:
        "Workloads fetch short-lived credentials from their local Unix socket; operators review readiness here without receiving workload key material.",
    });
    apiMock.activateProtocolProfile.mockResolvedValue({ profile: "eval", active: true, protocols: ["acme"] });
    apiMock.acmeUpstreamAuthorizations.mockResolvedValue({ items: [], never_validated_count: 0, guidance: "" });
    apiMock.acmeDNS01QualificationRuns.mockResolvedValue({ items: [] });
    apiMock.enrollmentDiagnostics.mockResolvedValue({ items: [], unknown_count: 0, guidance: "" });
    apiMock.revocationCaches.mockResolvedValue({
      observed: true,
      summary: { caches: 4, fresh: 3, stale: 1, empty: 0, error: 0 },
      guidance: "Signed relay metadata only.",
      items: [
        {
          agent_id: "relay-primary",
          agent_name: "plant-7-relay-a",
          cache_id: "issuer-a",
          segment: "plant-7",
          protocol: "crl",
          issuer_fingerprint: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          local_path: "/crl/issuer-a",
          status: "fresh",
          cached_responses: 1,
          fresh: true,
          signature_verified: true,
          this_update: "2026-08-12T13:00:00Z",
          next_update: "2026-08-12T15:00:00Z",
          last_validated_at: "2026-08-12T13:59:00Z",
          served_requests: 42,
          refused_requests: 1,
          signer_fingerprint: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
          reported_at: "2026-08-12T14:00:00Z",
          metadata_only: true,
        },
        {
          agent_id: "relay-primary",
          agent_name: "plant-7-relay-a",
          cache_id: "issuer-a",
          segment: "plant-7",
          protocol: "ocsp",
          issuer_fingerprint: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          local_path: "/ocsp/issuer-a",
          status: "stale",
          detail_code: "next_update_passed",
          cached_responses: 4,
          fresh: false,
          signature_verified: true,
          this_update: "2026-08-12T12:00:00Z",
          next_update: "2026-08-12T13:00:00Z",
          last_validated_at: "2026-08-12T12:59:00Z",
          served_requests: 11,
          refused_requests: 3,
          signer_fingerprint: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
          reported_at: "2026-08-12T14:00:00Z",
          metadata_only: true,
        },
      ],
    });
    apiMock.agentPage.mockResolvedValue({
      agents: [
        {
          id: "relay-primary",
          name: "plant-7-relay-a",
          status: "active",
          roles: ["network"],
          role_source: "certificate",
          inventory_report_path: "agent.mtls.ReportInventory",
          discovery_capabilities: [],
          relay_capabilities: [],
          workload_api: { state: "unreported", svids_issued: 0, detail: "Not reported." },
          enrollment_proxy: {
            state: "degraded",
            segment: "plant-7",
            public_url: "https://enrol.plant-7.example",
            healthy_upstreams: 1,
            unhealthy_upstreams: 1,
            unknown_upstreams: 0,
            upstream_failures: 2,
            forwarded_requests: 41,
            refused_requests: 3,
            last_forwarded_at: "2026-08-12T13:58:00Z",
            last_failover_at: "2026-08-12T13:57:00Z",
            reported_at: "2026-08-12T14:00:00Z",
            detail: "One configured control-plane endpoint is in cooldown.",
          },
        },
        {
          id: "relay-secondary",
          name: "plant-7-relay-b",
          status: "active",
          roles: ["network"],
          role_source: "certificate",
          inventory_report_path: "agent.mtls.ReportInventory",
          discovery_capabilities: [],
          relay_capabilities: [],
          workload_api: { state: "unreported", svids_issued: 0, detail: "Not reported." },
          enrollment_proxy: {
            state: "serving",
            segment: "plant-7",
            public_url: "https://enrol.plant-7.example",
            healthy_upstreams: 2,
            unhealthy_upstreams: 0,
            unknown_upstreams: 0,
            upstream_failures: 0,
            forwarded_requests: 9,
            refused_requests: 0,
            last_forwarded_at: "2026-08-12T13:59:00Z",
            reported_at: "2026-08-12T14:00:00Z",
            detail: "All configured control-plane endpoints are reachable.",
          },
        },
      ],
    });
    apiMock.acmeARIPosture.mockResolvedValue(ariPosture());
    apiMock.protocolStatuses.mockResolvedValue({
      source: "public_responder_probe",
      checked_at: "2026-06-26T14:00:00Z",
      items: [
        {
          protocol: "acme",
          endpoint: "/directory",
          enabled: true,
          served: true,
          status_code: 200,
          detail: "ACME directory responded.",
        },
        {
          protocol: "est",
          endpoint: "/.well-known/est/cacerts",
          enabled: true,
          served: true,
          status_code: 200,
          detail: "EST CA-certs responder returned a chain.",
        },
        {
          protocol: "scep",
          endpoint: "/scep?operation=GetCACaps",
          enabled: false,
          served: false,
          status_code: 404,
          detail: "SCEP responder is not mounted.",
        },
        {
          protocol: "cmp",
          endpoint: "/cmp",
          enabled: true,
          served: true,
          status_code: 405,
          detail: "CMP route is mounted and expects a PKIMessage request.",
        },
        {
          protocol: "spiffe",
          endpoint: "unix:///tmp/trstctl-spiffe-workload.sock",
          enabled: true,
          served: true,
          status_code: 0,
          detail: "Workload API socket configured.",
        },
        {
          protocol: "ssh",
          endpoint: "/ssh/ca",
          enabled: true,
          served: true,
          status_code: 200,
          detail: "SSH CA public-key endpoint responded.",
        },
        {
          protocol: "tsa",
          endpoint: "/tsa",
          enabled: true,
          served: true,
          status_code: 405,
          detail: "TSA route is mounted and expects a timestamp request.",
        },
      ],
    });
    apiMock.acmeDNS01Providers.mockResolvedValue({
      items: [
        provider("route53", "AWS Route 53", "hosted-dns", ["hosted_zone_id", "aws_secret_key_ref"], ["net.dial:route53.amazonaws.com"]),
        provider("googledns", "Google Cloud DNS", "hosted-dns", ["project", "managed_zone", "oauth_token_ref"], ["net.dial:dns.googleapis.com"]),
        provider("azuredns", "Azure DNS", "hosted-dns", ["subscription_id", "resource_group", "zone", "aad_token_ref"], ["net.dial:management.azure.com"]),
        provider("cloudflare", "Cloudflare DNS", "hosted-dns", ["zone_id", "api_token_ref"], ["net.dial:api.cloudflare.com"]),
        provider("rfc2136", "RFC 2136 dynamic DNS", "dynamic-dns", ["server", "zone", "tsig_secret_ref"], ["net.dial:authoritative-dns-server"]),
        provider("webhook", "Generic DNS webhook", "webhook", ["endpoint", "bearer_token_ref"], ["net.dial:webhook-host"]),
        provider("reference-dns", "reference-dns", "plugin", ["bearer_token_ref"], ["fs.write"], {
          admission_state: "verified",
          conformance: "signed-present-cleanup",
          provenance: "ed25519-signature-verified",
          provider_package: "signed-wasm:reference-dns",
        }),
      ],
    });
    apiMock.acmeDNS01ProviderConfigs.mockResolvedValue({
      items: [
        {
          id: "01900000-0000-7000-8000-000000000069",
          tenant_id: "11111111-1111-1111-1111-111111111111",
          name: "prod-cloudflare",
          provider: "cloudflare",
          zone: "example.test",
          challenge_domain: "_acme-challenge.example.test",
          delegation_target: "tenant-123.auth.acme-dns.example.net",
          credential_refs: { api_token_ref: "secret://dns/cloudflare/api-token" },
          config: { zone_id: "zone-prod" },
          caa_issuer_domain: "trstctl.example",
          allowed_methods: ["dns-01"],
          allow_wildcards: true,
          allow_upstream_dv: true,
          secret_handling: "credential_refs_only",
          created_at: "2026-06-26T14:00:00Z",
          updated_at: "2026-06-26T14:00:00Z",
        },
      ],
    });
    apiMock.mdmSCEPStatus.mockResolvedValue({
      runtime_gate: "served_scep_intune_validator_policy_driven",
      runtime_note: "The SCEP endpoint resolves enabled MDM SCEP policy trust_anchor_refs from the served secret store at challenge-validation time.",
      telemetry: {
        allowed: 7,
        denied: 2,
        replay_rejected: 1,
        last_failure_reason: "mdm: malformed challenge",
        last_transaction_id: "txn-mdm-deny",
        last_event_timestamp: "2026-06-26T14:03:00Z",
      },
      policies: [
        {
          id: "01900000-0000-7000-8000-000000000056",
          tenant_id: "11111111-1111-1111-1111-111111111111",
          name: "intune-mobile",
          provider: "intune",
          scep_profile: "mobile-scep",
          scep_endpoint: "https://trstctl.example.test/scep/pkiclient.exe",
          expected_audience: "https://ca.example.test/scep",
          challenge_mode: "intune-jws",
          trust_anchor_refs: { root_ca_ref: "secret://mdm/intune/root-ca" },
          profile_guidance: { challenge_source: "intune-jws" },
          enabled: true,
          rotation_version: 2,
          last_rotated_at: "2026-06-26T14:02:00Z",
          created_at: "2026-06-26T14:00:00Z",
          updated_at: "2026-06-26T14:02:00Z",
        },
      ],
    });
    apiMock.updateMDMSCEPPolicy.mockImplementation(async (_id, input) => ({
      ...(await apiMock.mdmSCEPStatus.mock.results[0]?.value)?.policies?.[0],
      ...input,
      id: "01900000-0000-7000-8000-000000000056",
      tenant_id: "11111111-1111-1111-1111-111111111111",
      rotation_version: 2,
      created_at: "2026-06-26T14:00:00Z",
      updated_at: "2026-06-26T14:04:00Z",
    }));
    const policyPreview = (input: Record<string, unknown>, operation: "create" | "update", policyID?: string) => ({
      capability: "F56",
      ready: true,
      effect_free: true,
      operation,
      ...(policyID ? { policy_id: policyID } : {}),
      name: input.name,
      provider: input.provider,
      scep_endpoint: input.scep_endpoint,
      scep_profile: input.scep_profile,
      challenge_mode: input.challenge_mode,
      enabled: input.enabled,
      ...(input.expected_audience ? { expected_audience: input.expected_audience } : {}),
      trust_anchor_reference_keys: Object.keys((input.trust_anchor_refs as Record<string, unknown>) ?? {}).sort(),
      profile_guidance: input.profile_guidance ?? {},
      durable_writes: ["mdm_scep_policies upsert", "mdm.scep_policy.upserted event"],
      outside_calls: [],
      signer_calls: 0,
      blockers: [],
      recovery_steps: ["Fix the named blocker and check the plan again.", "Retry the same save with the same idempotency key."],
      secret_data_handling: "Only reference field names are returned. Secret values are never accepted or rendered.",
    });
    apiMock.previewMDMSCEPPolicy.mockImplementation(async (input) => policyPreview(input, "create"));
    apiMock.previewMDMSCEPPolicyUpdate.mockImplementation(async (id, input) => policyPreview(input, "update", id));
    apiMock.createMDMSCEPPolicy.mockImplementation(async (input) => ({
      ...input,
      id: "01900000-0000-7000-8000-000000000057",
      tenant_id: "11111111-1111-1111-1111-111111111111",
      trust_anchor_refs: input.trust_anchor_refs ?? {},
      profile_guidance: input.profile_guidance ?? {},
      rotation_version: 1,
      created_at: "2026-06-26T14:06:00Z",
      updated_at: "2026-06-26T14:06:00Z",
    }));
    apiMock.previewMDMSCEPChallengeRotation.mockResolvedValue({
      capability: "F56",
      ready: true,
      effect_free: true,
      policy_id: "01900000-0000-7000-8000-000000000056",
      policy_name: "intune-mobile",
      current_version: 2,
      next_version: 3,
      durable_writes: ["mdm_scep_policies rotation version", "mdm.scep_challenge.rotated event"],
      outside_calls: [],
      signer_calls: 0,
      blockers: [],
      recovery_steps: ["Keep the current challenge active until this rotation commits.", "Retry safely if the request is interrupted."],
      secret_data_handling: "New challenge material is generated and stored behind the secret reference boundary; no secret value is returned.",
    });
    apiMock.deleteMDMSCEPPolicy.mockResolvedValue(undefined);
    apiMock.updateACMEDNS01ProviderConfig.mockImplementation(async (_id, input) => ({
      ...(await apiMock.acmeDNS01ProviderConfigs.mock.results[0]?.value)?.items?.[0],
      ...input,
      id: "01900000-0000-7000-8000-000000000069",
      tenant_id: "11111111-1111-1111-1111-111111111111",
      secret_handling: "credential_refs_only",
      created_at: "2026-06-26T14:00:00Z",
      updated_at: "2026-06-26T14:04:00Z",
    }));
    apiMock.deleteACMEDNS01ProviderConfig.mockResolvedValue(undefined);
  });

  it("starts with a plain method guide and keeps exact protocol machinery one level deeper", async () => {
    mountProtocols(null, false);

    expect(await screen.findByRole("heading", { name: "Choose how each machine asks" })).toBeInTheDocument();
    expect(screen.getByText("Automatic certificate renewal")).toBeInTheDocument();
    expect(screen.getByText("Machines request and renew certificates without a human step.")).toBeInTheDocument();
    expect(screen.getAllByRole("button", { name: "View setup" })).toHaveLength(7);
    const operations = screen.getByTestId("protocol-operational-details");
    expect(operations).not.toHaveAttribute("open");
    expect(within(operations).getByRole("heading", { name: "Protocol responder status" })).toBeInTheDocument();
  });

  it("lands View setup on the requested operator workspace", async () => {
    mountProtocols(null, false);
    await screen.findByRole("heading", { name: "Choose how each machine asks" });
    const cmpPanel = screen.getByRole("region", { name: "CMP readiness check" });
    const scrollIntoView = vi.fn();
    Object.defineProperty(cmpPanel, "scrollIntoView", { configurable: true, value: scrollIntoView });

    fireEvent.click(screen.getAllByRole("button", { name: "View setup" })[3]);

    await waitFor(() => expect(scrollIntoView).toHaveBeenCalledWith({ block: "start" }));
    expect(screen.getByTestId("protocol-operational-details")).toHaveAttribute("open");
    expect(cmpPanel).toHaveAttribute("id", "cmp-operator-panel");
  });

  it("keeps wide protocol tables inside the page at narrow viewports (AUD-125)", async () => {
    await renderProtocols();

    expect(screen.getByRole("region", { name: "How machines request credentials" })).toHaveClass("min-w-0", "[&>*]:min-w-0");
    expect(screen.getByRole("region", { name: "Client setup" })).toHaveClass("min-w-0", "[&>*]:min-w-0");
    expect(screen.getByRole("region", { name: "ACME" })).toHaveClass("min-w-0");
    for (const label of [
      "Enrollment protocol surfaces",
      "ACME DNS-01 provider coverage",
      "Tenant DNS-01 provider configurations",
      "MDM SCEP enrollment policies",
      "Copy ACME certbot command",
    ]) {
      expect(screen.getByRole("group", { name: label })).toHaveAttribute("tabindex", "0");
    }
  });

  it("renders ACME setup with live responder status", async () => {
    const writeText = installClipboardSpy();
    await renderProtocols();

    expect(screen.getByRole("heading", { name: "How machines request credentials" })).toBeInTheDocument();
    expect(screen.getAllByText("ACME directory, account, order, challenge, and certificate issuance flow").length).toBeGreaterThan(0);
    expect(screen.getAllByText("Protocol enabled").length).toBeGreaterThan(0);
    expect(screen.getAllByText("Tenant binding").length).toBeGreaterThan(0);
    expect(screen.getByRole("heading", { name: "Protocol responder status" })).toBeInTheDocument();
    expect(screen.getByText("Read-only responder probe")).toBeInTheDocument();
    expect(screen.getAllByText("Enabled").length).toBeGreaterThan(0);
    expect(screen.getAllByText("/directory").length).toBeGreaterThan(0);
    expect(screen.getAllByText("HTTP 200").length).toBeGreaterThan(0);
    expect(screen.getByText(/issuance refuses requests when no issuing CA\/profile/i)).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "DNS-01 providers" })).toBeInTheDocument();
    for (const name of ["AWS Route 53", "Google Cloud DNS", "Azure DNS", "Cloudflare DNS", "RFC 2136 dynamic DNS", "Generic DNS webhook"]) {
      expect(screen.getByText(name)).toBeInTheDocument();
    }
    expect(screen.getAllByText("present-validate-cleanup").length).toBeGreaterThanOrEqual(6);
    expect(screen.getByText("signed-present-cleanup")).toBeInTheDocument();
    expect(screen.getByText("Admission: verified")).toBeInTheDocument();
    expect(screen.getByText("Provenance: ed25519-signature-verified")).toBeInTheDocument();
    expect(screen.getByText("signed-wasm:reference-dns")).toBeInTheDocument();
    expect(screen.getAllByText("No raw secret fields").length).toBeGreaterThanOrEqual(6);
    expect(screen.getByText("tsig_secret_ref")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "DNS-01 provider configs" })).toBeInTheDocument();
    expect(screen.getByText("prod-cloudflare")).toBeInTheDocument();
    expect(screen.getAllByText("cloudflare").length).toBeGreaterThanOrEqual(2);
    expect(screen.getByText("example.test")).toBeInTheDocument();
    expect(screen.getByText("tenant-123.auth.acme-dns.example.net")).toBeInTheDocument();
    expect(screen.getByText("credential_refs_only")).toBeInTheDocument();
    expect(screen.getByText("Wildcards allowed")).toBeInTheDocument();
    expect(screen.getByText("CAA trstctl.example")).toBeInTheDocument();
    expect(screen.getAllByText("api_token_ref").length).toBeGreaterThanOrEqual(2);
    expect(screen.queryByText("secret://dns/cloudflare/api-token")).not.toBeInTheDocument();
    expect(screen.queryByText("zone-prod")).not.toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Intune / MDM SCEP policies" })).toBeInTheDocument();
    expect(screen.getByText("intune-mobile")).toBeInTheDocument();
    expect(screen.getByText("mobile-scep")).toBeInTheDocument();
    expect(screen.getByText("intune-jws")).toBeInTheDocument();
    expect(screen.getByText("Rotation version 2")).toBeInTheDocument();
    expect(screen.getByText("Challenge telemetry")).toBeInTheDocument();
    expect(screen.getByText("root_ca_ref")).toBeInTheDocument();
    expect(screen.getByText("mdm: malformed challenge")).toBeInTheDocument();
    expect(screen.queryByText("secret://mdm/intune/root-ca")).not.toBeInTheDocument();
    expect(screen.queryByText("Status unknown to console")).not.toBeInTheDocument();
    const mdmPanel = screen.getByRole("region", { name: "Intune / MDM SCEP policies" });
    expect(within(mdmPanel).queryByText(/^active$/i)).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Copy ACME certbot command" }));

    await waitFor(() => expect(writeText).toHaveBeenCalledWith(expect.stringContaining("--server https://trstctl.example.test/directory")));
    expect(writeText).toHaveBeenCalledWith(expect.not.stringMatching(/Bearer|token|password/i));
    expect(screen.getByText("Copied command without token material.")).toBeInTheDocument();
  });

  it("uses one server-owned, effect-free ACME plan for readiness, execution, and recovery", async () => {
    const writeText = installClipboardSpy();
    await renderProtocols();

    const panel = screen.getByRole("region", { name: "ACME readiness and next step" });
    expect(within(panel).getByText("Ready for ACME clients")).toBeInTheDocument();
    expect(within(panel).getByText("Connect an ACME client")).toBeInTheDocument();
    expect(within(panel).getByText("/directory")).toBeInTheDocument();
    expect(within(panel).getByText("1 active of 2 configured")).toBeInTheDocument();
    expect(within(panel).getByText("This check made no changes and contacted no external system.")).toBeInTheDocument();
    expect(within(panel).getByRole("heading", { name: "If a client fails" })).toBeInTheDocument();

    await userEvent.click(within(panel).getByRole("button", { name: "Copy ACME client command" }));
    expect(writeText).toHaveBeenCalledWith(expect.stringContaining("--server"));
    expect(writeText).toHaveBeenCalledWith(expect.stringContaining("/directory"));
  });

  it("activates only when the server offers the tenant-bound eval action, then reloads the plan", async () => {
    apiMock.acmeOperatorPlan
      .mockResolvedValueOnce({
        ready: false,
        served: false,
        tenant_bound: true,
        directory_path: "/directory",
        challenge_methods: ["http-01", "dns-01", "tls-alpn-01"],
        eab_required: false,
        eab_configured: 0,
        eab_active: 0,
        dns01_provider_configs: 0,
        issuing_profile: "",
        issuing_profile_ready: true,
        activation_mode: "eval_profile_event",
        activation_required: true,
        activation_available: true,
        next_action: {
          kind: "activate_eval_profile",
          label: "Activate evaluation protocols",
          detail: "Record one tenant-bound activation event.",
          method: "POST",
          path: "/api/v1/setup/protocols/activate",
        },
        blockers: ["The evaluation protocol profile is assembled but not active for this tenant."],
        warnings: [],
        recovery_steps: ["Retry activation with the same idempotency key."],
        preview_writes: [],
        preview_external_effects: [],
        generated_at: "2026-08-27T23:45:00Z",
      })
      .mockResolvedValueOnce({
        ...readyACMEOperatorPlan(),
        activation_mode: "eval_profile_event",
        next_action: { kind: "connect_acme_client", label: "Connect an ACME client", detail: "Use the directory.", method: "GET", path: "/directory" },
      });

    mountProtocols();
    const panel = screen.getByRole("region", { name: "ACME readiness and next step" });
    const activate = await within(panel).findByRole("button", { name: "Activate evaluation protocols" });
    await userEvent.click(activate);
    await waitFor(() => expect(apiMock.activateProtocolProfile).toHaveBeenCalledTimes(1));
    await waitFor(() => expect(apiMock.acmeOperatorPlan).toHaveBeenCalledTimes(2));
    expect(await within(panel).findByText("Ready for ACME clients")).toBeInTheDocument();
  });

  it("renders exact per-segment enrollment relay topology and durable failover evidence", async () => {
    await renderProtocols();
    fireEvent.click(screen.getByText("Network-segment evidence"));

    const panel = await screen.findByRole("region", { name: "Enrollment relay topology" });
    expect(within(panel).getByText("plant-7")).toBeInTheDocument();
    expect(within(panel).getByText("2 relays")).toBeInTheDocument();
    expect(within(panel).getByText("plant-7-relay-a")).toBeInTheDocument();
    expect(within(panel).getByText("plant-7-relay-b")).toBeInTheDocument();
    expect(within(panel).getAllByText("https://enrol.plant-7.example")).toHaveLength(2);
    expect(within(panel).getByText("1 verified / 1 unavailable / 0 unverified")).toBeInTheDocument();
    expect(within(panel).getByText("2 upstream failures")).toBeInTheDocument();
    expect(within(panel).getByText("Last forwarded: Aug 12, 2026, 1:59 PM")).toBeInTheDocument();
    expect(within(panel).getByText("Last control-plane failover: Aug 12, 2026, 1:57 PM")).toBeInTheDocument();
  });

  it("does not call relays redundant when their stock-client authorities differ", async () => {
    const page = await apiMock.agentPage();
    apiMock.agentPage.mockResolvedValue({
      ...page,
      agents: page.agents.map((agent: { id: string; enrollment_proxy: { public_url: string } }) =>
        agent.id === "relay-secondary" ? { ...agent, enrollment_proxy: { ...agent.enrollment_proxy, public_url: "https://other.plant-7.example" } } : agent,
      ),
    });
    await renderProtocols();
    fireEvent.click(screen.getByText("Network-segment evidence"));

    const panel = await screen.findByRole("region", { name: "Enrollment relay topology" });
    expect(within(panel).queryByText("2 relays")).not.toBeInTheDocument();
    expect(within(panel).getAllByText("1 relay")).toHaveLength(2);
  });

  it("renders signed multi-issuer revocation-cache freshness without cache bytes or upstream locations", async () => {
    await renderProtocols();
    fireEvent.click(screen.getByText("Network-segment evidence"));

    const panel = await screen.findByRole("region", { name: "Revocation cache by segment" });
    expect(within(panel).getByText("3 fresh / 1 stale / 0 empty / 0 error")).toBeInTheDocument();
    expect(within(panel).getAllByText("issuer-a")).toHaveLength(2);
    expect(within(panel).getByText("/crl/issuer-a")).toBeInTheDocument();
    expect(within(panel).getByText("/ocsp/issuer-a")).toBeInTheDocument();
    expect(within(panel).getAllByText("Issuer signature verified")).toHaveLength(2);
    expect(within(panel).getByText("next_update_passed")).toBeInTheDocument();
    expect(within(panel).getByText("4 cached responses")).toBeInTheDocument();
    expect(within(panel).queryByText(/BEGIN|\.der|upstream\.example|application\/ocsp-response/i)).not.toBeInTheDocument();
  });

  it("keeps unobserved revocation posture distinct from a healthy empty cache", async () => {
    apiMock.revocationCaches.mockResolvedValueOnce({
      observed: false,
      summary: { caches: 0, fresh: 0, stale: 0, empty: 0, error: 0 },
      guidance: "No signed relay report.",
      items: [],
    });
    mountProtocols();

    expect(await screen.findByText("No revocation cache has reported")).toBeInTheDocument();
    expect(screen.getByText(/does not prove that an isolated segment has fresh revocation data/i)).toBeInTheDocument();
  });

  it("renders the authenticated tenant's durable diagnosis, count, timestamp, and remediation", async () => {
    apiMock.enrollmentDiagnostics.mockResolvedValue({
      items: [
        {
          protocol: "acme",
          step: "validation",
          cause: "challenge_not_visible",
          summary: "The authority could not see the challenge this system published.",
          remediation: "Check propagation from an external resolver.",
          actionable: true,
          observed_at: "2026-08-10T05:10:00Z",
          count: 3,
        },
      ],
      unknown_count: 0,
      guidance: "These are durable tenant-scoped events, collapsed into the 200 most recent distinct diagnoses for this tenant.",
    });

    await renderProtocols();

    expect(await screen.findByRole("heading", { name: "Enrolment failures" })).toBeInTheDocument();
    expect(screen.getByText(/durable tenant-scoped events/)).toBeInTheDocument();
    expect(screen.getByText("The authority could not see the challenge this system published.")).toBeInTheDocument();
    expect(screen.getByText("Check propagation from an external resolver.")).toBeInTheDocument();
    expect(screen.getByText(/3×, last at/)).toBeInTheDocument();
  });

  it("shows exact refusal evidence and queues a network proof with issue permission", async () => {
    const initialDiagnostics: EnrollmentDiagnosticList = {
      items: [
        {
          id: "diag-acme-validation-1",
          protocol: "acme",
          step: "validation",
          cause: "challenge_not_visible",
          summary: "The authority could not see the challenge this system published.",
          remediation: "Check propagation from an external resolver.",
          actionable: true,
          observed_at: "2026-08-10T05:10:00Z",
          count: 1,
          operation_ref: "order/order-42/authorization/authz-9/challenge/chal-7",
          identity_ref: "dns/api.example.test",
          endpoint_ref: "https/api.example.test:443",
          verification_kind: "endpoint.verify",
          verification_address: "api.example.test:443",
          verification_server_name: "api.example.test",
        },
      ],
      unknown_count: 0,
      guidance: "Each row is one exact failed operation.",
    };
    let resolveVerificationPoll: (value: typeof initialDiagnostics) => void = () => undefined;
    const verificationPoll = new Promise<typeof initialDiagnostics>((resolve) => {
      resolveVerificationPoll = resolve;
    });
    apiMock.enrollmentDiagnostics.mockResolvedValueOnce(initialDiagnostics).mockImplementationOnce(() => verificationPoll);
    apiMock.proveEnrollmentDiagnosticFixed.mockResolvedValue({
      diagnostic_id: "diag-acme-validation-1",
      verification_endpoint_id: "verify-1",
      status: "queued",
      queued_at: "2026-08-13T04:00:00Z",
      result_path: "/api/v1/endpoints/verifications/verify-1",
    });
    mountProtocols(["certs:issue"]);

    const panel = await screen.findByRole("region", { name: "Enrolment failures" });
    expect(within(panel).getByText("order/order-42/authorization/authz-9/challenge/chal-7")).toBeInTheDocument();
    expect(within(panel).getByText("dns/api.example.test")).toBeInTheDocument();
    expect(within(panel).getByText("https/api.example.test:443")).toBeInTheDocument();

    await userEvent.click(within(panel).getByRole("button", { name: "Prove fixed" }));
    await waitFor(() => expect(apiMock.proveEnrollmentDiagnosticFixed).toHaveBeenCalledWith("diag-acme-validation-1"));
    expect(within(panel).getByText("Queued for network verification")).toBeInTheDocument();
    expect(within(panel).queryByRole("link", { name: "Signed verification evidence" })).not.toBeInTheDocument();

    resolveVerificationPoll({
      ...initialDiagnostics,
      items: [
        {
          ...initialDiagnostics.items[0],
          verification_endpoint_id: "verify-1",
          verification_status: "verified",
          verification_evidence_digest: "sha256:network-proof",
          verification_agent: "relay-7",
          verification_result_path: "/api/v1/endpoints/verifications/verify-1",
        },
      ],
    });
    expect(await within(panel).findByText("Verified fixed")).toBeInTheDocument();
    expect(within(panel).getByText("sha256:network-proof")).toBeInTheDocument();
    expect(within(panel).getByRole("link", { name: "Signed verification evidence" })).toHaveAttribute("href", "/api/v1/endpoints/verifications/verify-1");
  });

  it("does not render the prove-fixed control for a read-only operator", async () => {
    apiMock.enrollmentDiagnostics.mockResolvedValue({
      items: [
        {
          id: "diag-read-only",
          protocol: "scep",
          step: "authorize",
          cause: "client_cert_rejected",
          summary: "The client certificate presented for enrollment was refused.",
          remediation: "Check the client certificate chain.",
          actionable: true,
          observed_at: "2026-08-10T05:10:00Z",
          count: 1,
          operation_ref: "scep:txn-read-only",
          identity_ref: "device:SERIAL-7",
          endpoint_ref: "https/scep.example.test:443",
          verification_kind: "endpoint.verify",
          verification_address: "scep.example.test:443",
        },
      ],
      unknown_count: 0,
      guidance: "Each row is one exact failed operation.",
    });
    mountProtocols(["certs:read"]);

    const panel = await screen.findByRole("region", { name: "Enrolment failures" });
    expect(within(panel).queryByRole("button", { name: "Prove fixed" })).not.toBeInTheDocument();
    expect(within(panel).getByText("No network proof queued")).toBeInTheDocument();
  });

  it("links signed green evidence instead of claiming a refusal is fixed from operator intent", async () => {
    apiMock.enrollmentDiagnostics.mockResolvedValue({
      items: [
        {
          id: "diag-est-issuance-1",
          protocol: "est",
          step: "issuance",
          cause: "ca_policy_rejected",
          summary: "The CA rejected this exact enrollment.",
          actionable: true,
          observed_at: "2026-08-10T05:10:00Z",
          count: 1,
          operation_ref: "idempotency/est-42",
          identity_ref: "csr-sha256/abc123",
          endpoint_ref: "https/est.example.test:443",
          verification_status: "verified",
          verification_evidence_digest: "sha256:feedface",
          verification_agent: "network-relay-7",
          verification_checked_at: "2026-08-13T04:05:00Z",
          verification_result_path: "/api/v1/endpoints/verifications/verify-est-1",
        },
      ],
      unknown_count: 0,
      guidance: "Each row is one exact failed operation.",
    });
    mountProtocols(["certs:issue"]);

    const panel = await screen.findByRole("region", { name: "Enrolment failures" });
    expect(within(panel).getByText("Verified fixed")).toBeInTheDocument();
    expect(within(panel).getByText("network-relay-7")).toBeInTheDocument();
    expect(within(panel).getByText("sha256:feedface")).toBeInTheDocument();
    expect(within(panel).getByRole("link", { name: "Signed verification evidence" })).toHaveAttribute("href", "/api/v1/endpoints/verifications/verify-est-1");
  });

  it("renders ARI publication and scheduler-consumption truth without mutation controls", async () => {
    await renderProtocols();

    const panel = screen.getByRole("region", { name: "ACME Renewal Information (ARI)" });
    expect(within(panel).getByText("Publishing")).toBeInTheDocument();
    expect(within(panel).getByText("payments-api")).toBeInTheDocument();
    expect(within(panel).getByText("01900000-0000-7000-8000-000000000046")).toBeInTheDocument();
    expect(within(panel).getByText("Consumed")).toBeInTheDocument();
    expect(within(panel).getByText("ARI window")).toBeInTheDocument();
    expect(within(panel).queryByRole("button")).not.toBeInTheDocument();
  });

  it("follows ARI cursors so certificates after the first page are not hidden", async () => {
    const firstItems = Array.from({ length: 100 }, (_, index) => ({
      ...ariPosture().items[0],
      certificate_id: `01900000-0000-7000-8000-${String(index).padStart(12, "0")}`,
      identity_name: `first-page-${index}`,
    }));
    apiMock.acmeARIPosture
      .mockResolvedValueOnce(
        ariPosture({
          summary: { affected_certificates: 100, published: 100, scheduler_pending: 0, scheduler_consumed: 100, scheduler_failed: 0 },
          items: firstItems,
          next_cursor: "page-two",
        }),
      )
      .mockResolvedValueOnce(
        ariPosture({
          summary: { affected_certificates: 1, published: 1, scheduler_pending: 0, scheduler_consumed: 1, scheduler_failed: 0 },
          items: [{ ...ariPosture().items[0], certificate_id: "01900000-0000-7000-8000-999999999999", identity_name: "second-page-cert" }],
        }),
      );
    mountProtocols();

    const panel = screen.getByRole("region", { name: "ACME Renewal Information (ARI)" });
    expect(await within(panel).findByText("second-page-cert")).toBeInTheDocument();
    expect(apiMock.acmeARIPosture).toHaveBeenNthCalledWith(1, { limit: 100, cursor: undefined });
    expect(apiMock.acmeARIPosture).toHaveBeenNthCalledWith(2, { limit: 100, cursor: "page-two" });
  });

  it("shows an ARI-consumed execution failure as failed, not green", async () => {
    const failed = ariPosture();
    apiMock.acmeARIPosture.mockResolvedValueOnce(
      ariPosture({
        summary: { affected_certificates: 1, published: 1, scheduler_pending: 0, scheduler_consumed: 1, scheduler_failed: 1 },
        items: [{ ...failed.items[0], scheduler_status: "failed", scheduler_consumed: true }],
      }),
    );
    mountProtocols();

    const panel = screen.getByRole("region", { name: "ACME Renewal Information (ARI)" });
    expect(await within(panel).findByText("Failed")).toBeInTheDocument();
    expect(within(panel).queryByText("Consumed")).not.toBeInTheDocument();
  });

  it("renders the ARI loading state before the read contract resolves", async () => {
    let resolvePosture!: (value: ReturnType<typeof ariPosture>) => void;
    apiMock.acmeARIPosture.mockReturnValueOnce(
      new Promise<ReturnType<typeof ariPosture>>((resolve) => {
        resolvePosture = resolve;
      }),
    );
    mountProtocols();

    const panel = screen.getByRole("region", { name: "ACME Renewal Information (ARI)" });
    expect(await within(panel).findByText("Loading ARI renewal posture.")).toBeInTheDocument();

    resolvePosture(ariPosture());
    expect(await within(panel).findByText("payments-api")).toBeInTheDocument();
  });

  it("renders an honest empty ARI posture", async () => {
    apiMock.acmeARIPosture.mockResolvedValueOnce(
      ariPosture({
        summary: { affected_certificates: 0, published: 0, scheduler_pending: 0, scheduler_consumed: 0, scheduler_failed: 0 },
        items: [],
      }),
    );
    mountProtocols();

    const panel = screen.getByRole("region", { name: "ACME Renewal Information (ARI)" });
    expect(await within(panel).findByText("No ARI renewal windows yet")).toBeInTheDocument();
    expect(panel.querySelector('[data-state-primitive="empty"]')).toBeInTheDocument();
  });

  it("denies ARI posture without lifecycle:read and does not call the endpoint", async () => {
    mountProtocols(["issuers:read"]);

    const panel = screen.getByRole("region", { name: "ACME Renewal Information (ARI)" });
    expect(await within(panel).findByText("Your session cannot read this tenant’s ARI renewal posture.")).toBeInTheDocument();
    expect(panel.querySelector('[data-state-primitive="permission-denied"]')).toBeInTheDocument();
    expect(apiMock.acmeARIPosture).not.toHaveBeenCalled();
  });

  it("renders unavailable when the ARI posture provider is not assembled", async () => {
    apiMock.acmeARIPosture.mockRejectedValueOnce(new ApiError(503, JSON.stringify({ detail: "ACME ARI posture is not assembled" })));
    mountProtocols();

    const panel = screen.getByRole("region", { name: "ACME Renewal Information (ARI)" });
    expect(await within(panel).findByText("ARI posture unavailable")).toBeInTheDocument();
    expect(panel.querySelector('[data-state-primitive="unavailable"]')).toBeInTheDocument();
  });

  it("renders a mutation-free ARI failure state", async () => {
    apiMock.acmeARIPosture.mockRejectedValue(new ApiError(500, JSON.stringify({ detail: "tenant t2 exists" })));
    mountProtocols();

    const panel = screen.getByRole("region", { name: "ACME Renewal Information (ARI)" });
    expect(await within(panel).findByText("ARI posture could not be loaded", {}, { timeout: 3_000 })).toBeInTheDocument();
    expect(panel.querySelector('[data-state-primitive="error"]')).toBeInTheDocument();
    expect(within(panel).queryByText("tenant t2 exists")).not.toBeInTheDocument();
    expect(within(panel).queryByRole("button")).not.toBeInTheDocument();
  });

  it("fails closed with the served responder error instead of stale status", async () => {
    apiMock.protocolStatuses.mockRejectedValueOnce(new Error("responder registry offline"));
    mountProtocols();

    expect(await screen.findByText("Protocol status check failed")).toBeInTheDocument();
    expect(screen.getByText("responder registry offline")).toBeInTheDocument();
    expect(screen.queryByText("ACME directory responded.")).not.toBeInTheDocument();
  });

  it("renders honest empty states and endpoint fallbacks when every served collection is empty", async () => {
    apiMock.protocolStatuses.mockResolvedValueOnce({ source: "public_responder_probe", checked_at: "", items: [] });
    apiMock.acmeDNS01Providers.mockResolvedValueOnce({ items: [] });
    apiMock.acmeDNS01ProviderConfigs.mockResolvedValueOnce({ items: [] });
    apiMock.mdmSCEPStatus.mockResolvedValueOnce({
      runtime_gate: "",
      runtime_note: "",
      telemetry: { allowed: 0, denied: 0, replay_rejected: 0 },
      policies: [],
    });
    mountProtocols();

    expect(await screen.findByText("DNS-01 providers unavailable")).toBeInTheDocument();
    const dnsConfigSection = screen.getByRole("heading", { name: "DNS-01 provider configs" }).closest("section");
    const mdmSection = screen.getByRole("heading", { name: "Intune / MDM SCEP policies" }).closest("section");
    expect(dnsConfigSection).not.toBeNull();
    expect(mdmSection).not.toBeNull();
    expect(within(dnsConfigSection as HTMLElement).getByText("No DNS-01 provider configured")).toBeInTheDocument();
    expect(within(mdmSection as HTMLElement).getByText("No MDM SCEP policy configured")).toBeInTheDocument();
    expect(dnsConfigSection?.querySelector('[data-state-primitive="error"]')).not.toBeInTheDocument();
    expect(mdmSection?.querySelector('[data-state-primitive="error"]')).not.toBeInTheDocument();
    expect(screen.getAllByText("Not browser-readable").length).toBeGreaterThan(0);
    expect(screen.getByText("unix:///tmp/trstctl-spiffe-workload.sock")).toBeInTheDocument();
    expect(screen.getByText("Unknown")).toBeInTheDocument();
  });

  it("degrades honestly for partial older provider, config, and policy records", async () => {
    apiMock.acmeDNS01Providers.mockResolvedValueOnce({
      items: [
        provider("legacy-dns", "Legacy DNS", "hosted-dns", [], [], {
          served: false,
          admission_state: undefined,
          provenance: undefined,
          propagation_preflight: false,
          credential_reference_fields: undefined,
          secret_fields: undefined,
          capabilities: undefined,
        }),
      ],
    });
    apiMock.acmeDNS01ProviderConfigs.mockResolvedValueOnce({
      items: [
        {
          id: "01900000-0000-7000-8000-000000000070",
          tenant_id: "11111111-1111-1111-1111-111111111111",
          name: "legacy-config",
          provider: "legacy-dns",
          allowed_methods: undefined,
          allow_wildcards: false,
          credential_refs: undefined,
          config: {},
          secret_handling: "credential_refs_only",
          created_at: "2026-06-26T14:00:00Z",
          updated_at: "2026-06-26T14:00:00Z",
        },
      ],
    });
    apiMock.mdmSCEPStatus.mockResolvedValueOnce({
      runtime_gate: "served",
      runtime_note: "",
      telemetry: { allowed: 0, denied: 0, replay_rejected: 0 },
      policies: [
        {
          id: "01900000-0000-7000-8000-000000000057",
          tenant_id: "11111111-1111-1111-1111-111111111111",
          name: "legacy-mdm",
          provider: "jamf",
          scep_profile: "legacy",
          scep_endpoint: "https://trstctl.example.test/scep/legacy",
          challenge_mode: "hmac-dynamic",
          trust_anchor_refs: undefined,
          profile_guidance: {},
          enabled: false,
          rotation_version: 1,
          created_at: "2026-06-26T14:00:00Z",
          updated_at: "2026-06-26T14:00:00Z",
        },
      ],
    });
    mountProtocols();

    expect(await screen.findByText("Legacy DNS")).toBeInTheDocument();
    expect(screen.getByText("Zone unbound")).toBeInTheDocument();
    expect(screen.getByText("No method policy")).toBeInTheDocument();
    expect(screen.getByText("Wildcards denied")).toBeInTheDocument();
    expect(screen.getByText("Disabled")).toBeInTheDocument();
  });

  it("renders EST, SCEP, and CMP with live responder routes and no transcript placeholders", async () => {
    await renderProtocols();

    expect(screen.getAllByText("CA certificate download and simple enrollment flow").length).toBeGreaterThan(0);
    expect(screen.getAllByText("SCEP CA discovery and PKI operation flow").length).toBeGreaterThan(0);
    expect(screen.getAllByText("CMP enrollment request flow").length).toBeGreaterThan(0);
    expect(screen.getAllByText("RA key file").length).toBe(2);
    expect(screen.getByText("/scep?operation=GetCACaps")).toBeInTheDocument();
    expect(screen.getByText("SCEP responder is not mounted.")).toBeInTheDocument();
    expect(screen.getAllByText("Off").length).toBeGreaterThan(0);
    expect(screen.getByText("/cmp")).toBeInTheDocument();
    expect(screen.getByText("CMP route is mounted and expects a PKIMessage request.")).toBeInTheDocument();
    expect(screen.getAllByText("Served").length).toBeGreaterThan(0);
    expect(screen.queryByText("EST enrollment transcript coming soon")).not.toBeInTheDocument();
    expect(screen.queryByText("SCEP enrollment transcript coming soon")).not.toBeInTheDocument();
    expect(screen.queryByText("CMP enrollment transcript coming soon")).not.toBeInTheDocument();
    expect(screen.queryByText(/does not invent order, challenge, or transcript data/i)).not.toBeInTheDocument();
  });

  it("previews, runs, observes, and safely retries the exact EST path without enrolling", async () => {
    const user = userEvent.setup();
    await renderProtocols();

    const panel = screen.getByRole("region", { name: "EST connection check" });
    expect(within(panel).getByText("Safety boundary: no certificate, CSR, token, or private key will be created, sent, or stored.")).toBeInTheDocument();
    expect(within(panel).getByText("GET /.well-known/est/cacerts")).toBeInTheDocument();
    expect(within(panel).getByText("GET /.well-known/est/csrattrs")).toBeInTheDocument();
    expect(within(panel).getByText("POST /.well-known/est/simpleenroll")).toBeInTheDocument();
    expect(apiMock.estQualification).not.toHaveBeenCalled();

    await user.click(within(panel).getByRole("button", { name: "Run safe EST check" }));

    await waitFor(() => expect(apiMock.estQualification).toHaveBeenCalledTimes(1));
    expect((await within(panel).findAllByText("EST is ready for a client")).length).toBeGreaterThanOrEqual(1);
    expect(within(panel).getByText("Enrollment refused the credential-free probe before reading a CSR.")).toBeInTheDocument();
    expect(within(panel).getByText("No certificate was issued by this check.")).toBeInTheDocument();

    apiMock.estQualification.mockResolvedValueOnce({
      checked_at: "2026-08-28T12:01:00Z",
      passed: false,
      checks: [
        {
          id: "ca-chain",
          method: "GET",
          endpoint: "/.well-known/est/cacerts",
          expected: "HTTP 200 with a base64 PKCS#7 CA chain",
          status_code: 503,
          passed: false,
          detail: "The CA chain responder returned HTTP 503.",
        },
      ],
    });
    await user.click(within(panel).getByRole("button", { name: "Run again" }));

    expect((await within(panel).findAllByText("EST needs attention")).length).toBeGreaterThanOrEqual(1);
    expect(
      within(panel).getByText("Keep authentication strict. Repair the named responder or signer configuration, then run this same check again."),
    ).toBeInTheDocument();
  });

  it("previews, runs, observes, and safely retries the exact SCEP path without enrolling", async () => {
    const user = userEvent.setup();
    await renderProtocols();

    const panel = screen.getByRole("region", { name: "SCEP connection check" });
    expect(
      within(panel).getByText(
        "Safety boundary: no PKI message, CSR, challenge, credential, certificate request, or private key will be created, sent, or stored.",
      ),
    ).toBeInTheDocument();
    expect(within(panel).getByText("GET /scep?operation=GetCACaps")).toBeInTheDocument();
    expect(within(panel).getByText("GET /scep?operation=GetCACert")).toBeInTheDocument();
    expect(within(panel).getByText("POST /scep?operation=PKIOperation")).toBeInTheDocument();
    expect(apiMock.scepQualification).not.toHaveBeenCalled();

    await user.click(within(panel).getByRole("button", { name: "Run safe SCEP check" }));

    await waitFor(() => expect(apiMock.scepQualification).toHaveBeenCalledTimes(1));
    expect((await within(panel).findAllByText("SCEP is ready for a client")).length).toBeGreaterThanOrEqual(1);
    expect(within(panel).getByText("Enrollment refused the empty PKI message before reading a CSR or challenge.")).toBeInTheDocument();
    expect(within(panel).getByText("No certificate was issued by this check.")).toBeInTheDocument();

    apiMock.scepQualification.mockResolvedValueOnce({
      checked_at: "2026-08-28T12:01:00Z",
      passed: false,
      checks: [
        {
          id: "ca-material",
          method: "GET",
          endpoint: "/scep?operation=GetCACert",
          expected: "HTTP 200 with a structurally valid CA certificate or CA/RA bundle",
          status_code: 503,
          passed: false,
          detail: "The CA-material responder returned HTTP 503.",
        },
      ],
    });
    await user.click(within(panel).getByRole("button", { name: "Run again" }));

    expect((await within(panel).findAllByText("SCEP needs attention")).length).toBeGreaterThanOrEqual(1);
    expect(
      within(panel).getByText(
        "Keep the challenge gate and CMS checks strict. Repair the named responder, CA/RA, or signer configuration, then run this same check again.",
      ),
    ).toBeInTheDocument();
  });

  it("previews, runs, observes, and safely retries exact CMP readiness without a PKIMessage", async () => {
    const user = userEvent.setup();
    await renderProtocols();

    const panel = screen.getByRole("region", { name: "CMP readiness check" });
    expect(
      within(panel).getByText(
        "Safety boundary: this reads in-memory readiness only. It sends no PKIMessage, CSR, client certificate, credential, or private key; it makes no write, signer call, or network call.",
      ),
    ).toBeInTheDocument();
    expect(within(panel).getByText("Endpoint and tenant")).toBeInTheDocument();
    expect(within(panel).getByText("Protection identity and trust")).toBeInTheDocument();
    expect(within(panel).getByText("Profile and isolated signer")).toBeInTheDocument();
    expect(within(panel).getByText("Bounded capacity")).toBeInTheDocument();
    expect(apiMock.cmpQualification).not.toHaveBeenCalled();

    await user.click(within(panel).getByRole("button", { name: "Run safe CMP check" }));

    await waitFor(() => expect(apiMock.cmpQualification).toHaveBeenCalledTimes(1));
    expect((await within(panel).findAllByText("CMP is ready for a protected client")).length).toBeGreaterThanOrEqual(1);
    expect(within(panel).getByText("device-90d")).toBeInTheDocument();
    expect(within(panel).getByText("Client may request only its own names")).toBeInTheDocument();
    expect(within(panel).getByText("2 approved trust anchor(s)")).toBeInTheDocument();
    expect(within(panel).getByText(/0 writes · 0 outside calls · 0 signer calls/i)).toBeInTheDocument();
    expect(within(panel).getByText(/not proof that a client has enrolled/i)).toBeInTheDocument();

    apiMock.cmpQualification.mockResolvedValueOnce({
      checked_at: "2026-08-28T12:01:00Z",
      ready: false,
      effect_free: true,
      endpoint: "/cmp",
      profile: "device-90d",
      binding_mode: "subject-bound",
      client_trust_anchor_count: 0,
      checks: [
        {
          id: "client-trust",
          label: "Client protection trust",
          passed: false,
          detail: "This gate is not ready in the running process.",
          recovery: "Configure the approved client or RA chain and restart; anonymous CMP enrollment stays refused.",
        },
      ],
      preview_writes: [],
      preview_external_effects: [],
      preview_signer_calls: [],
      proof: ["In-memory only.", "No request material.", "No effects."],
      blockers: ["Client protection trust: configure the approved chain."],
    });
    await user.click(within(panel).getByRole("button", { name: "Run again" }));

    expect((await within(panel).findAllByText("CMP needs attention")).length).toBeGreaterThanOrEqual(1);
    expect(within(panel).getByText(/anonymous CMP enrollment stays refused/i)).toBeInTheDocument();
  });

  it("renders bounded CMP refusal receipts and copy-safe interoperable OpenSSL guidance", async () => {
    const writeText = installClipboardSpy();
    apiMock.enrollmentDiagnostics.mockResolvedValueOnce({
      items: [
        {
          id: "cmp-refusal-1",
          protocol: "cmp",
          step: "authorize",
          cause: "client_cert_rejected",
          summary: "The CMP protection certificate did not chain to an approved client trust anchor.",
          remediation: "Install the approved client or RA chain; do not enable anonymous enrollment.",
          actionable: true,
          observed_at: "2026-08-28T11:58:00Z",
          count: 2,
          operation_ref: "cmp:sha256:bounded-reference",
        },
      ],
      unknown_count: 0,
      guidance: "Bounded tenant evidence.",
    });
    await renderProtocols();

    const panel = screen.getByRole("region", { name: "CMP readiness check" });
    expect(await within(panel).findByText(/did not chain to an approved client trust anchor/i)).toBeInTheDocument();
    expect(within(panel).getByText("cmp:sha256:bounded-reference")).toBeInTheDocument();
    expect(within(panel).getByText(/Raw PKIMessages, CSRs, protection certificates, keys, and secrets are never rendered/i)).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Copy CMP OpenSSL p10cr command" }));
    await waitFor(() => expect(writeText).toHaveBeenCalled());
    const command = String(writeText.mock.calls.at(-1)?.[0]);
    for (const required of [
      "-cert cmp-client.pem",
      "-key cmp-client.key",
      "-extracerts cmp-client.pem",
      "-srvcert cmp-ra.pem",
      "-reqout request.der",
      "-rspout response.der",
    ]) {
      expect(command).toContain(required);
    }
    expect(command).not.toMatch(/BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY|password=|secret=/i);
  });

  it("automatically proves SPIFFE UDS readiness and keeps recovery effect-free", async () => {
    const user = userEvent.setup();
    await renderProtocols();

    const panel = screen.getByRole("region", { name: "SPIFFE workload identity readiness" });
    await waitFor(() => expect(apiMock.spiffeQualification).toHaveBeenCalledTimes(1));
    expect(await within(panel).findAllByText("SPIFFE is ready for a workload client")).toHaveLength(1);
    expect(within(panel).getByText("workloads.example.test")).toBeInTheDocument();
    expect(within(panel).getByText("unix:///run/trstctl-spiffe/workload.sock")).toBeInTheDocument();
    expect(within(panel).getByText("1 active rule(s)")).toBeInTheDocument();
    expect(within(panel).getByText("5 supported operations")).toBeInTheDocument();
    expect(within(panel).getByText(/0 writes · 0 outside calls · 0 signer calls · 0 identities minted/i)).toBeInTheDocument();
    expect(within(panel).getByText(/control-plane socket is a compatibility path/i)).toBeInTheDocument();

    apiMock.spiffeQualification.mockResolvedValueOnce({
      checked_at: "2026-08-29T12:01:00Z",
      ready: false,
      effect_free: true,
      trust_domain: "workloads.example.test",
      socket_uri: "unix:///run/trstctl-spiffe/workload.sock",
      transport: "unix",
      socket_mode: "",
      registration_entry_count: 1,
      local_socket_deprecated: true,
      supported_operations: ["FetchX509SVID", "FetchX509Bundles", "FetchJWTSVID", "FetchJWTBundles", "ValidateJWTSVID"],
      checks: [
        {
          id: "socket-listening",
          label: "Unix socket listening",
          passed: false,
          detail: "This gate is not ready in the running process.",
          recovery: "Repair the socket directory, mount, permissions, or server lifecycle, then confirm the exact path again.",
        },
      ],
      preview_writes: [],
      preview_external_effects: [],
      preview_signer_calls: [],
      proof: ["Server posture only.", "No workload call.", "No effects."],
      blockers: ["Unix socket listening: repair the socket."],
      client_boundary: "Workloads fetch short-lived credentials from their local Unix socket.",
    });
    await user.click(within(panel).getByRole("button", { name: "Run again" }));

    expect(await within(panel).findAllByText("SPIFFE needs attention")).toHaveLength(1);
    expect(within(panel).getByText(/Repair the socket directory, mount, permissions/i)).toBeInTheDocument();
  });

  it("renders SPIFFE, SSH CA, and TSA setup without exposing private key material", async () => {
    const writeText = installClipboardSpy();
    await renderProtocols();

    expect(screen.getAllByText("Workload API socket issuing X.509-SVID and JWT-SVID credentials").length).toBeGreaterThan(0);
    expect(screen.getAllByText("Trust domain").length).toBeGreaterThan(0);
    expect(screen.getByText("unix:///tmp/trstctl-spiffe-workload.sock")).toBeInTheDocument();
    expect(screen.getByText("Workload API socket configured.")).toBeInTheDocument();
    expect(screen.getByText(/X.509-SVID and JWT-SVID support/i)).toBeInTheDocument();

    expect(screen.getAllByText("SSH CA public key, user/host certificate issuance, and revocation list flow").length).toBeGreaterThan(0);
    expect(screen.getByText("SSH CA public-key endpoint responded.")).toBeInTheDocument();
    expect(screen.getByText(/OpenSSH binary KRL/i)).toBeInTheDocument();

    expect(screen.getAllByText("RFC 3161 timestamp request flow").length).toBeGreaterThan(0);
    expect(screen.getByText("TSA certificate file")).toBeInTheDocument();
    expect(screen.getByText("/tsa")).toBeInTheDocument();
    expect(screen.getByText("TSA route is mounted and expects a timestamp request.")).toBeInTheDocument();
    expect(screen.getByText(/openssl ts -query/i)).toBeInTheDocument();
    expect(screen.getByText(/openssl ts -verify/i)).toBeInTheDocument();
    expect(screen.queryByText("SPIFFE live workload status coming soon")).not.toBeInTheDocument();
    expect(screen.queryByText("SSH issue/revoke log coming soon")).not.toBeInTheDocument();
    expect(screen.queryByText("TSA issuance health coming soon")).not.toBeInTheDocument();
    expect(screen.queryByText(/BEGIN PRIVATE KEY/)).not.toBeInTheDocument();
    expect(screen.queryByText(/BEGIN OPENSSH PRIVATE KEY/)).not.toBeInTheDocument();
    expect(screen.queryByText(/SVID private key:/i)).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Copy TSA HTTP POST command" }));

    await waitFor(() => expect(writeText).toHaveBeenCalledWith(expect.stringContaining("https://trstctl.example.test/tsa")));
    expect(writeText).toHaveBeenCalledWith(expect.not.stringMatching(/PRIVATE KEY|password/i));
  });

  it("hides DNS validation, CAA, wildcard, and MDM fixture sections", async () => {
    await renderProtocols();

    expect(screen.queryByRole("heading", { name: "ACME DNS validation" })).not.toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Intune / MDM enrollment" })).not.toBeInTheDocument();
    expect(screen.queryByText("ACME responder")).not.toBeInTheDocument();
    expect(screen.queryByText("secret://dns/cloudflare/prod")).not.toBeInTheDocument();
    expect(screen.queryByText("_acme-challenge.example.test CNAME _acme-challenge.acme-validation.example.net")).not.toBeInTheDocument();
    expect(screen.queryByText("No CAA record")).not.toBeInTheDocument();
    expect(screen.queryByText("CAA allowed issuer")).not.toBeInTheDocument();
    expect(screen.queryByText("CAA denied issuer")).not.toBeInTheDocument();
    expect(screen.queryByText("CAA DNS failure")).not.toBeInTheDocument();
    expect(screen.queryByText("Wildcard CAA")).not.toBeInTheDocument();
    expect(screen.queryByText("TLS-ALPN-01")).not.toBeInTheDocument();
    expect(screen.queryByText("challenge-required")).not.toBeInTheDocument();
    expect(screen.queryByText("challenge-missing")).not.toBeInTheDocument();
    expect(screen.queryByText("scep-disabled")).not.toBeInTheDocument();
    expect(screen.queryByText(/Raw DNS provider tokens are never typed into this console/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/Wildcard issuance requires explicit operator acknowledgement/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/run outside this console today/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/Challenge rotation and enrollment failures stay in fixture form/i)).not.toBeInTheDocument();
    expect(screen.queryByRole("textbox", { name: /token|api token|provider token/i })).not.toBeInTheDocument();
    // Preflight is now a real console feature (CLI parity), so it is intentionally present.
    expect(screen.queryByRole("button", { name: /activate|save provider/i })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /issue wildcard|acknowledge wildcard|run challenge/i })).not.toBeInTheDocument();
    // Challenge rotation is now a real console feature (CLI parity), so it is intentionally present.
    expect(screen.queryByRole("button", { name: /sync intune|retry enrollment/i })).not.toBeInTheDocument();
  });

  it("runs DNS-01 preflight with explicit evidence and renders pass, fail, and skipped checks", async () => {
    const user = userEvent.setup();
    apiMock.acmeDNS01Preflight
      .mockRejectedValueOnce(new Error("preflight worker offline"))
      .mockResolvedValueOnce({
        config_id: "01900000-0000-7000-8000-000000000069",
        domain: "*.api.example.test",
        wildcard: true,
        selected_method: "dns-01",
        record_name: "_acme-challenge.api.example.test",
        method_rationale: "Wildcard orders require DNS-01.",
        ready: false,
        caa_policy: {
          status: "denied",
          source: "authoritative_live_dns",
          configured_issuer: "trstctl.example",
          governing_name: "example.test",
          wildcard: true,
          relevant_tag: "issuewild",
          records: [{ flag: 0, tag: "issuewild", value: "other.ca" }],
          allowed_issuers: ["other.ca"],
          recommended_records: ['example.test CAA 0 issuewild "trstctl.example"'],
          recovery_steps: ["Publish the recommended record.", "Wait for DNS, then check again."],
          fail_closed: true,
        },
        checks: [
          { name: "delegation", status: "pass", detail: "Delegation reached the configured target." },
          { name: "CAA", status: "fail", detail: "The issuer is not allowed." },
          { name: "port 80", status: "skipped", detail: "Not used by DNS-01." },
        ],
        failed_checks: ["CAA"],
      })
      .mockResolvedValueOnce({
        config_id: "01900000-0000-7000-8000-000000000069",
        domain: "api.example.test",
        wildcard: false,
        selected_method: "dns-01",
        record_name: "_acme-challenge.api.example.test",
        ready: true,
        caa_policy: {
          status: "allowed",
          source: "authoritative_live_dns",
          configured_issuer: "trstctl.example",
          governing_name: "example.test",
          wildcard: false,
          relevant_tag: "issue",
          records: [{ flag: 0, tag: "issue", value: "trstctl.example" }],
          allowed_issuers: ["trstctl.example"],
          recommended_records: [],
          recovery_steps: ["No CAA change is required."],
          fail_closed: true,
        },
        checks: [{ name: "delegation", status: "pass", detail: "Ready." }],
        failed_checks: [],
      });
    await renderProtocols();

    await user.click(screen.getByRole("button", { name: "Preflight check prod-cloudflare" }));
    const dialog = screen.getByRole("dialog", { name: "DNS-01 preflight: prod-cloudflare" });
    await user.type(within(dialog).getByRole("textbox", { name: "Domain" }), "*.api.example.test");
    await user.selectOptions(within(dialog).getByRole("combobox", { name: "Method override (optional)" }), "dns-01");
    await user.type(within(dialog).getByRole("textbox", { name: "Expected TXT value (optional)" }), "expected-proof");
    await user.type(within(dialog).getByRole("textbox", { name: "Observed TXT records (optional, one per line)" }), "first-proof\n\nsecond-proof");
    await user.click(within(dialog).getByRole("button", { name: "Run preflight" }));
    expect(await within(dialog).findByText("preflight worker offline")).toBeInTheDocument();
    await user.click(within(dialog).getByRole("button", { name: "Run preflight" }));

    await waitFor(() =>
      expect(apiMock.acmeDNS01Preflight).toHaveBeenLastCalledWith({
        config_id: "01900000-0000-7000-8000-000000000069",
        domain: "*.api.example.test",
        expected_txt: "expected-proof",
        method_override: "dns-01",
        observed_txt: ["first-proof", "second-proof"],
      }),
    );
    expect(await within(dialog).findByText("Not ready")).toBeInTheDocument();
    expect(within(dialog).getByText("Wildcard orders require DNS-01.")).toBeInTheDocument();
    expect(within(dialog).getByText(/Failed checks:.*CAA/)).toBeInTheDocument();
    expect(within(dialog).getByRole("region", { name: "CAA issuance policy" })).toHaveTextContent("CAA blocks this issuer");
    expect(within(dialog).getByText('example.test CAA 0 issuewild "trstctl.example"')).toBeInTheDocument();
    expect(within(dialog).getByRole("status", { name: "Preflight result for *.api.example.test" })).toHaveFocus();

    await user.clear(within(dialog).getByRole("textbox", { name: "Domain" }));
    await user.type(within(dialog).getByRole("textbox", { name: "Domain" }), "api.example.test");
    await user.click(within(dialog).getByRole("button", { name: "Re-run preflight" }));
    expect(await within(dialog).findByText("Ready")).toBeInTheDocument();
    expect(within(dialog).getByRole("region", { name: "CAA issuance policy" })).toHaveTextContent("CAA allows this issuer");
    expect(within(dialog).getByRole("status", { name: "Preflight result for api.example.test" })).toHaveFocus();
    expect(apiMock.acmeDNS01Preflight).toHaveBeenCalledTimes(3);
  });

  it("reviews, executes, observes, and recovers an admitted signed DNS plugin without exposing secrets", async () => {
    const user = userEvent.setup();
    apiMock.acmeDNS01ProviderConfigs.mockResolvedValue({
      items: [
        {
          id: "01900000-0000-7000-8000-000000000070",
          tenant_id: "11111111-1111-1111-1111-111111111111",
          name: "signed-reference-dns",
          provider: "reference-dns",
          zone: "example.test",
          credential_refs: { bearer_token_ref: "secret://dns/reference/bearer-token" },
          config: { endpoint: "https://dns-provider.invalid" },
          allowed_methods: ["dns-01"],
          allow_wildcards: true,
          secret_handling: "credential_refs_only",
          created_at: "2026-08-29T18:00:00Z",
          updated_at: "2026-08-29T18:00:00Z",
        },
      ],
    });
    const preview = {
      ready: true,
      effect_free: true,
      config_id: "01900000-0000-7000-8000-000000000070",
      config_name: "signed-reference-dns",
      provider: "reference-dns",
      domain: "api.example.test",
      record_name: "_acme-challenge.api.example.test",
      wildcard: false,
      credential_reference_fields: ["bearer_token_ref"],
      checks: [
        { id: "domain-policy", label: "Domain policy", passed: true, detail: "This config covers api.example.test.", recovery: "Choose a matching config." },
        { id: "cleanup", label: "Cleanup path", passed: true, detail: "Cleanup uses the same bounded outbox.", recovery: "Retry cleanup from history." },
      ],
      blockers: [],
      preview_writes: [],
      preview_external_effects: [],
      preview_signer_calls: [],
      execute_writes: ["Record immutable qualification evidence."],
      execute_external_effects: ["Publish one random TXT probe.", "Remove that exact TXT probe."],
      execute_signer_calls: [],
      recovery_steps: ["If cleanup needs attention, use Retry cleanup from qualification history."],
      least_privilege_checklist: ["Grant TXT edit access only for _acme-challenge.api.example.test."],
      secret_data_handling: "The browser receives reference field names only; it never receives provider credentials or the TXT probe value.",
    };
    const recoveryRequired = {
      id: "01900000-0000-7000-8000-000000000169",
      config_id: preview.config_id,
      config_name: preview.config_name,
      provider: preview.provider,
      domain: preview.domain,
      record_name: preview.record_name,
      status: "recovery_required",
      stage: "cleanup",
      propagation_status: "passed",
      cleanup_status: "failed",
      error_category: "cleanup_delivery_failed",
      attempts: 5,
      started_at: "2026-08-29T18:00:00Z",
      completed_at: "2026-08-29T18:00:03Z",
      duration_ms: 3000,
      recovery_steps: ["Repair provider access, then retry cleanup from this row."],
      secret_data_handling: "No TXT value, provider credential, credential reference value, idempotency key, or raw worker error is returned.",
    };
    const passed = { ...recoveryRequired, status: "passed", stage: "complete", cleanup_status: "delivered", error_category: undefined };
    apiMock.previewACMEDNS01Qualification.mockResolvedValue(preview);
    apiMock.runACMEDNS01Qualification.mockResolvedValue(recoveryRequired);
    apiMock.retryACMEDNS01QualificationCleanup.mockResolvedValue(passed);
    apiMock.acmeDNS01QualificationRuns.mockResolvedValueOnce({ items: [] }).mockResolvedValue({ items: [recoveryRequired] });

    await renderProtocols();
    await user.click(screen.getByRole("button", { name: "Test DNS-01 provider signed-reference-dns" }));
    const dialog = screen.getByRole("dialog", { name: "Test DNS-01 provider: signed-reference-dns" });
    expect(within(dialog).getByRole("heading", { name: "Verified signed plugin" })).toBeInTheDocument();
    expect(within(dialog).getByText("Ed25519 signature verified")).toBeInTheDocument();
    expect(within(dialog).getByText("DNS publish and cleanup contract passed")).toBeInTheDocument();
    expect(within(dialog).getByText("fs.write")).toBeInTheDocument();
    expect(within(dialog).getByText("signed-wasm:reference-dns")).toBeInTheDocument();
    await user.type(within(dialog).getByRole("textbox", { name: "Domain to test" }), "api.example.test");
    await user.click(within(dialog).getByRole("button", { name: "Review safe test" }));

    expect(await within(dialog).findByText("Safe to test")).toBeInTheDocument();
    expect(within(dialog).getByText("This review made no writes, outside calls, or signing calls.")).toBeInTheDocument();
    expect(within(dialog).getByText("Publish one random TXT probe.")).toBeInTheDocument();
    expect(within(dialog).getByText("Remove that exact TXT probe.")).toBeInTheDocument();
    expect(within(dialog).getByText("bearer_token_ref")).toBeInTheDocument();
    expect(within(dialog).getByText(/Grant TXT edit access only/)).toBeInTheDocument();
    expect(within(dialog).queryByText("secret://dns/cloudflare/api-token")).not.toBeInTheDocument();
    expect(within(dialog).queryByRole("textbox", { name: /token|secret|txt value/i })).not.toBeInTheDocument();

    await user.click(within(dialog).getByRole("button", { name: "Publish, verify, and clean up" }));
    expect(await within(dialog).findByText("Cleanup needs attention")).toBeInTheDocument();
    expect(within(dialog).getByRole("region", { name: "DNS-01 provider test result" })).toHaveFocus();
    expect(within(dialog).getByText("cleanup_delivery_failed")).toBeInTheDocument();
    expect(within(dialog).getByText("Repair provider access, then retry cleanup from this row.")).toBeInTheDocument();
    await user.click(within(dialog).getByRole("button", { name: "Retry cleanup" }));
    expect(await within(dialog).findByText("Provider test passed")).toBeInTheDocument();
    expect(within(dialog).getByRole("region", { name: "DNS-01 provider test result" })).toHaveFocus();

    expect(apiMock.previewACMEDNS01Qualification).toHaveBeenCalledWith(preview.config_id, { domain: "api.example.test" });
    expect(apiMock.runACMEDNS01Qualification).toHaveBeenCalledWith(preview.config_id, { domain: "api.example.test" });
    expect(apiMock.retryACMEDNS01QualificationCleanup).toHaveBeenCalledWith(recoveryRequired.id);
  });

  it("shows and proves the exact fail-closed CNAME isolation path for a delegated provider", async () => {
    const user = userEvent.setup();
    const configId = "01900000-0000-7000-8000-000000000071";
    const target = "tenant-123.auth.acme-dns.example.net";
    const recordName = "_acme-challenge.api.example.test";
    apiMock.acmeDNS01ProviderConfigs.mockResolvedValue({
      items: [
        {
          id: configId,
          tenant_id: "11111111-1111-1111-1111-111111111111",
          name: "isolated-validation-zone",
          provider: "webhook",
          zone: "example.test",
          delegation_target: target,
          credential_refs: { bearer_token_ref: "secret://dns/isolated/bearer-token" },
          config: { endpoint: "https://dns-provider.invalid" },
          allowed_methods: ["dns-01"],
          allow_wildcards: false,
          secret_handling: "credential_refs_only",
          created_at: "2026-08-29T18:00:00Z",
          updated_at: "2026-08-29T18:00:00Z",
        },
      ],
    });
    const preview = {
      ready: true,
      effect_free: true,
      config_id: configId,
      config_name: "isolated-validation-zone",
      provider: "webhook",
      domain: "api.example.test",
      record_name: recordName,
      wildcard: false,
      credential_reference_fields: ["bearer_token_ref"],
      checks: [],
      blockers: [],
      preview_writes: [],
      preview_external_effects: [],
      preview_signer_calls: [],
      execute_writes: ["Record immutable qualification evidence."],
      execute_external_effects: ["Publish and remove one server-generated probe."],
      execute_signer_calls: [],
      recovery_steps: ["Repair the CNAME and run the test again."],
      least_privilege_checklist: ["Grant TXT access only in the isolated validation zone."],
      secret_data_handling: "No secret values leave the server.",
    };
    const failed = {
      id: "01900000-0000-7000-8000-000000000171",
      config_id: configId,
      config_name: preview.config_name,
      provider: preview.provider,
      domain: preview.domain,
      record_name: recordName,
      status: "failed",
      stage: "publish",
      propagation_status: "not_run",
      cleanup_status: "delivered",
      error_category: "publish_delivery_failed",
      attempts: 1,
      started_at: "2026-08-29T18:00:00Z",
      completed_at: "2026-08-29T18:00:01Z",
      duration_ms: 1000,
      recovery_steps: ["Repair authoritative DNS or CNAME delegation, then run a new provider test."],
      secret_data_handling: "No secret values leave the server.",
    };
    const passed = {
      ...failed,
      id: "01900000-0000-7000-8000-000000000172",
      status: "passed",
      stage: "complete",
      propagation_status: "passed",
      error_category: undefined,
      attempts: 2,
    };
    apiMock.previewACMEDNS01Qualification.mockResolvedValue(preview);
    apiMock.runACMEDNS01Qualification.mockResolvedValueOnce(failed).mockResolvedValueOnce(passed);
    apiMock.acmeDNS01QualificationRuns.mockResolvedValue({ items: [] });

    await renderProtocols();
    await user.click(screen.getByRole("button", { name: "Test DNS-01 provider isolated-validation-zone" }));
    const dialog = screen.getByRole("dialog", { name: "Test DNS-01 provider: isolated-validation-zone" });
    await user.type(within(dialog).getByRole("textbox", { name: "Domain to test" }), "api.example.test");
    await user.click(within(dialog).getByRole("button", { name: "Review safe test" }));

    expect(await within(dialog).findByRole("heading", { name: "CNAME guard configured; live proof pending" })).toBeInTheDocument();
    expect(within(dialog).getByRole("region", { name: "DNS-01 provider test plan" })).toHaveFocus();
    expect(within(dialog).getAllByText(recordName).length).toBeGreaterThan(0);
    expect(within(dialog).getAllByText(target).length).toBeGreaterThan(0);
    expect(within(dialog).getByText(`Create ${recordName} CNAME ${target}.`)).toBeInTheDocument();
    expect(within(dialog).getByText(/stops before the provider write/i)).toBeInTheDocument();

    await user.click(within(dialog).getByRole("button", { name: "Publish, verify, and clean up" }));
    expect(await within(dialog).findByRole("heading", { name: "CNAME isolation is not proved" })).toBeInTheDocument();
    expect(within(dialog).getByRole("region", { name: "DNS-01 provider test result" })).toHaveFocus();
    expect(within(dialog).getByText("Repair authoritative DNS or CNAME delegation, then run a new provider test.")).toBeInTheDocument();

    await user.click(within(dialog).getByRole("button", { name: "Publish, verify, and clean up" }));
    expect(await within(dialog).findByRole("heading", { name: "CNAME isolation proved by this live test" })).toBeInTheDocument();
    expect(within(dialog).getByRole("region", { name: "DNS-01 provider test result" })).toHaveFocus();
    expect(apiMock.runACMEDNS01Qualification).toHaveBeenCalledTimes(2);
  });

  it("creates the first DNS-01 provider config from the blank console using references only", async () => {
    const user = userEvent.setup();
    apiMock.acmeDNS01ProviderConfigs.mockResolvedValueOnce({ items: [] });
    apiMock.createACMEDNS01ProviderConfig.mockResolvedValue({
      id: "01900000-0000-7000-8000-000000000170",
      tenant_id: "11111111-1111-1111-1111-111111111111",
      name: "first-cloudflare",
      provider: "cloudflare",
      zone: "example.test",
      credential_refs: { api_token_ref: "secret://dns/cloudflare/first" },
      config: { zone_id: "zone-first" },
      allowed_methods: ["dns-01"],
      allow_wildcards: false,
      allow_upstream_dv: false,
      secret_handling: "credential_refs_only",
      created_at: "2026-08-29T18:00:00Z",
      updated_at: "2026-08-29T18:00:00Z",
    });
    await renderProtocols();

    await user.click(screen.getByRole("button", { name: "Add DNS-01 provider" }));
    const dialog = screen.getByRole("dialog", { name: "Add DNS-01 provider config" });
    await user.type(within(dialog).getByRole("textbox", { name: "Config name" }), "first-cloudflare");
    await user.selectOptions(within(dialog).getByRole("combobox", { name: "Provider" }), "cloudflare");
    await user.type(within(dialog).getByRole("textbox", { name: "Zone (optional)" }), "example.test");
    fireEvent.change(within(dialog).getByRole("textbox", { name: "Provider config JSON (optional)" }), {
      target: { value: '{"zone_id":"zone-first"}' },
    });
    fireEvent.change(within(dialog).getByRole("textbox", { name: /Credential references JSON \(optional\)/ }), {
      target: { value: '{"api_token_ref":"secret://dns/cloudflare/first"}' },
    });
    await user.click(within(dialog).getByRole("checkbox", { name: "dns-01" }));
    await user.click(within(dialog).getByRole("button", { name: "Add provider" }));

    await waitFor(() => expect(screen.queryByRole("dialog", { name: "Add DNS-01 provider config" })).not.toBeInTheDocument());
    expect(apiMock.createACMEDNS01ProviderConfig).toHaveBeenCalledWith(
      expect.objectContaining({
        name: "first-cloudflare",
        provider: "cloudflare",
        zone: "example.test",
        allowed_methods: ["dns-01"],
        config: { zone_id: "zone-first" },
        credential_refs: { api_token_ref: "secret://dns/cloudflare/first" },
      }),
    );
    expect(screen.getAllByText("first-cloudflare").length).toBeGreaterThan(0);
    expect(screen.queryByRole("textbox", { name: /token|api token|provider token/i })).not.toBeInTheDocument();
  });

  it("validates and saves the served DNS-01 config form without accepting raw non-object JSON", async () => {
    const user = userEvent.setup();
    await renderProtocols();

    await user.click(screen.getByRole("button", { name: "Edit DNS-01 config prod-cloudflare" }));
    const dialog = screen.getByRole("dialog", { name: "Edit DNS-01 provider config: prod-cloudflare" });
    const configJSON = within(dialog).getByRole("textbox", { name: "Provider config JSON (optional)" });
    const refsJSON = within(dialog).getByRole("textbox", { name: /Credential references JSON \(optional\)/ });

    fireEvent.change(configJSON, { target: { value: "{" } });
    await user.click(within(dialog).getByRole("button", { name: "Save config" }));
    expect(await within(dialog).findByText(/Provider config must be valid JSON/)).toBeInTheDocument();
    expect(apiMock.updateACMEDNS01ProviderConfig).not.toHaveBeenCalled();

    fireEvent.change(configJSON, { target: { value: '{"zone_id":"zone-next"}' } });
    fireEvent.change(refsJSON, { target: { value: "[]" } });
    await user.click(within(dialog).getByRole("button", { name: "Save config" }));
    expect(await within(dialog).findByText("Credential references must be a JSON object.")).toBeInTheDocument();

    fireEvent.change(refsJSON, { target: { value: '{"api_token_ref":"secret://dns/cloudflare/next"}' } });
    fireEvent.change(within(dialog).getByRole("textbox", { name: "Config name" }), { target: { value: "prod-cloudflare-next" } });
    fireEvent.change(within(dialog).getByRole("textbox", { name: "Zone (optional)" }), { target: { value: "" } });
    fireEvent.click(within(dialog).getByRole("checkbox", { name: "dns-01" }));
    fireEvent.click(within(dialog).getByRole("checkbox", { name: "http-01" }));
    fireEvent.click(within(dialog).getByRole("checkbox", { name: "Allow wildcard issuance" }));
    apiMock.updateACMEDNS01ProviderConfig.mockRejectedValueOnce(new Error("config service offline"));

    await user.click(within(dialog).getByRole("button", { name: "Save config" }));
    expect(await within(dialog).findByText("config service offline")).toBeInTheDocument();
    await user.click(within(dialog).getByRole("button", { name: "Save config" }));

    await waitFor(() => expect(screen.queryByRole("dialog", { name: /Edit DNS-01 provider config/ })).not.toBeInTheDocument());
    expect(apiMock.updateACMEDNS01ProviderConfig).toHaveBeenLastCalledWith(
      "01900000-0000-7000-8000-000000000069",
      expect.objectContaining({
        name: "prod-cloudflare-next",
        provider: "cloudflare",
        allow_wildcards: false,
        allowed_methods: ["http-01"],
        config: { zone_id: "zone-next" },
        credential_refs: { api_token_ref: "secret://dns/cloudflare/next" },
      }),
    );
    expect(screen.getAllByText("prod-cloudflare-next").length).toBeGreaterThan(0);
  });

  it("previews and saves an edited MDM SCEP policy without rendering secret reference values", async () => {
    const user = userEvent.setup();
    await renderProtocols();

    await user.click(screen.getByRole("button", { name: "Edit SCEP policy intune-mobile" }));
    const dialog = screen.getByRole("dialog", { name: "Edit MDM enrollment policy" });
    await user.selectOptions(within(dialog).getByRole("combobox", { name: "MDM provider" }), "jamf");
    fireEvent.click(within(dialog).getByRole("checkbox", { name: "Allow enrollment after this policy is saved" }));
    await user.click(within(dialog).getByRole("button", { name: "Next" }));
    const anchors = within(dialog).getByRole("textbox", { name: "Trust reference names (JSON)" });
    const guidance = within(dialog).getByRole("textbox", { name: "MDM profile guidance (JSON)" });

    fireEvent.change(anchors, { target: { value: "{" } });
    await user.click(within(dialog).getByRole("button", { name: "Check the plan" }));
    expect(await within(dialog).findByText("Enter one JSON object, such as {}.")).toBeInTheDocument();

    fireEvent.change(anchors, { target: { value: '{"root_ca_ref":"secret://mdm/intune/root-ca-next"}' } });
    fireEvent.change(guidance, { target: { value: "[]" } });
    await user.click(within(dialog).getByRole("button", { name: "Check the plan" }));
    expect((await within(dialog).findAllByText("Enter one JSON object, such as {}.")).length).toBeGreaterThan(0);

    fireEvent.change(guidance, { target: { value: '{"challenge_source":"hmac-dynamic"}' } });
    await user.selectOptions(within(dialog).getByRole("combobox", { name: "Challenge check" }), "hmac-dynamic");
    fireEvent.change(within(dialog).getByRole("textbox", { name: "Expected audience (optional)" }), { target: { value: "" } });
    await user.click(within(dialog).getByRole("button", { name: "Check the plan" }));

    expect(await within(dialog).findByText("Ready to save")).toBeInTheDocument();
    expect(within(dialog).getByText("This check made no writes, outside calls, or signing calls.")).toBeInTheDocument();
    expect(within(dialog).getByText("root_ca_ref")).toBeInTheDocument();
    expect(within(dialog).queryByText("secret://mdm/intune/root-ca-next")).not.toBeInTheDocument();
    await user.click(within(dialog).getByRole("button", { name: "Save policy" }));

    await waitFor(() => expect(screen.queryByRole("dialog", { name: "Edit MDM enrollment policy" })).not.toBeInTheDocument());
    expect(apiMock.previewMDMSCEPPolicyUpdate).toHaveBeenCalledWith(
      "01900000-0000-7000-8000-000000000056",
      expect.objectContaining({ provider: "jamf", challenge_mode: "hmac-dynamic", enabled: false }),
    );
    expect(apiMock.updateMDMSCEPPolicy).toHaveBeenCalledWith(
      "01900000-0000-7000-8000-000000000056",
      expect.objectContaining({
        provider: "jamf",
        challenge_mode: "hmac-dynamic",
        enabled: false,
        trust_anchor_refs: { root_ca_ref: "secret://mdm/intune/root-ca-next" },
        profile_guidance: { challenge_source: "hmac-dynamic" },
      }),
    );
  });

  it("creates the first MDM SCEP policy through the same effect-free review", async () => {
    const user = userEvent.setup();
    const status = await apiMock.mdmSCEPStatus();
    apiMock.mdmSCEPStatus.mockClear();
    apiMock.mdmSCEPStatus.mockResolvedValueOnce({ ...status, policies: [] });
    await renderProtocols();

    expect(screen.getByText("No MDM SCEP policy configured")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Add MDM policy" }));
    const dialog = screen.getByRole("dialog", { name: "Create MDM enrollment policy" });
    await user.type(within(dialog).getByRole("textbox", { name: "Policy name" }), "intune-first");
    await user.type(within(dialog).getByRole("textbox", { name: "Certificate profile" }), "mobile-scep");
    await user.click(within(dialog).getByRole("button", { name: "Next" }));
    await user.click(within(dialog).getByRole("button", { name: "Check the plan" }));

    expect(await within(dialog).findByText("Ready to save")).toBeInTheDocument();
    await user.click(within(dialog).getByRole("button", { name: "Create policy" }));
    await waitFor(() => expect(screen.queryByRole("dialog", { name: "Create MDM enrollment policy" })).not.toBeInTheDocument());
    expect(apiMock.previewMDMSCEPPolicy).toHaveBeenCalledWith(expect.objectContaining({ name: "intune-first", provider: "intune" }));
    expect(apiMock.createMDMSCEPPolicy).toHaveBeenCalledWith(expect.objectContaining({ name: "intune-first", scep_profile: "mobile-scep" }));
    expect(screen.getAllByText("intune-first").length).toBeGreaterThan(0);
  });

  it("rotates and deletes SCEP policy evidence and deletes DNS config only after exact-name confirmation", async () => {
    const user = userEvent.setup();
    await renderProtocols();
    const mdm = await apiMock.mdmSCEPStatus.mock.results[0].value;
    apiMock.rotateMDMSCEPChallenge.mockRejectedValueOnce(new Error("rotation worker offline")).mockResolvedValueOnce({
      policy: { ...mdm.policies[0], rotation_version: 3, last_rotated_at: "2026-06-26T14:05:00Z" },
    });

    await user.click(screen.getByRole("button", { name: "Rotate challenge for intune-mobile" }));
    let dialog = screen.getByRole("dialog", { name: "Rotate SCEP challenge for intune-mobile?" });
    expect(await within(dialog).findByText("Rotation version 2 will become version 3.")).toBeInTheDocument();
    expect(within(dialog).getByText(/This check made no writes/)).toBeInTheDocument();
    expect(within(dialog).getByText("Retry safely if the request is interrupted.")).toBeInTheDocument();
    await user.click(within(dialog).getByRole("button", { name: "Rotate challenge" }));
    expect(await within(dialog).findByText("rotation worker offline")).toBeInTheDocument();
    await user.click(within(dialog).getByRole("button", { name: "Rotate challenge" }));
    await waitFor(() => expect(screen.queryByRole("dialog", { name: /Rotate SCEP challenge/ })).not.toBeInTheDocument());
    expect(screen.getByText("Rotation version 3")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Delete SCEP policy intune-mobile" }));
    dialog = screen.getByRole("alertdialog", { name: /Delete SCEP policy.*intune-mobile/ });
    const deletePolicy = within(dialog).getByRole("button", { name: "Yes, delete policy" });
    expect(deletePolicy).toBeDisabled();
    await user.type(within(dialog).getByRole("textbox", { name: "Type policy name to confirm" }), "intune-mobile");
    apiMock.deleteMDMSCEPPolicy.mockRejectedValueOnce(new Error("policy delete offline"));
    await user.click(deletePolicy);
    expect(await within(dialog).findByRole("alert")).toHaveTextContent("policy delete offline");
    await user.click(deletePolicy);
    await waitFor(() => expect(screen.queryByRole("button", { name: "Delete SCEP policy intune-mobile" })).not.toBeInTheDocument());
    expect(apiMock.deleteMDMSCEPPolicy).toHaveBeenCalledWith("01900000-0000-7000-8000-000000000056");

    await user.click(screen.getByRole("button", { name: "Delete DNS-01 config prod-cloudflare" }));
    dialog = screen.getByRole("alertdialog", { name: /Delete DNS-01 provider config.*prod-cloudflare/ });
    const deleteConfig = within(dialog).getByRole("button", { name: "Yes, delete config" });
    expect(deleteConfig).toBeDisabled();
    await user.type(within(dialog).getByRole("textbox", { name: "Type config name to confirm" }), "prod-cloudflare");
    apiMock.deleteACMEDNS01ProviderConfig.mockRejectedValueOnce(new Error("config delete offline"));
    await user.click(deleteConfig);
    expect(await within(dialog).findByRole("alert")).toHaveTextContent("config delete offline");
    await user.click(deleteConfig);
    await waitFor(() => expect(screen.queryByRole("button", { name: "Delete DNS-01 config prod-cloudflare" })).not.toBeInTheDocument());
    expect(apiMock.deleteACMEDNS01ProviderConfig).toHaveBeenCalledWith("01900000-0000-7000-8000-000000000069");
  });

  // Editing a provider config must not silently revoke upstream-DV consent
  // (epic B7).
  //
  // The dialog does a PUT, which REPLACES the config. A field the form does not
  // send comes back as its zero value, so an operator who opened this dialog to
  // fix a typo in the zone name would have turned off upstream domain
  // validation without being told — and discovered it one renewal cycle later,
  // when a process that was supposed to need no human suddenly did.
  //
  // The flag is also a permission rather than a preference, so it is shown
  // rather than merely preserved: publishing into a zone on an external CA's
  // behalf is not what credentials added for the server direction granted.
  it("preserves and exposes upstream-DV consent when a config is edited", async () => {
    const user = userEvent.setup();
    await renderProtocols();

    await user.click(screen.getByRole("button", { name: "Edit DNS-01 config prod-cloudflare" }));
    const dialog = await screen.findByRole("dialog");

    const consent = within(dialog).getByRole("checkbox", { name: /allow upstream domain validation/i });
    expect(consent).toBeChecked();

    // Change something unrelated, exactly as an operator would: the first text
    // field in the dialog, leaving the consent checkbox untouched.
    const firstField = within(dialog).getAllByRole("textbox")[0];
    await user.clear(firstField);
    await user.type(firstField, "prod-cloudflare-renamed");
    await user.click(within(dialog).getByRole("button", { name: /save/i }));

    await waitFor(() => expect(apiMock.updateACMEDNS01ProviderConfig).toHaveBeenCalled());
    const [, input] = apiMock.updateACMEDNS01ProviderConfig.mock.calls[0];
    expect(input.allow_upstream_dv).toBe(true);
  });

  // And turning it OFF must actually turn it off — a consent control that only
  // ever grants is not a control.
  it("revokes upstream-DV consent when the operator clears it", async () => {
    const user = userEvent.setup();
    await renderProtocols();

    await user.click(screen.getByRole("button", { name: "Edit DNS-01 config prod-cloudflare" }));
    const dialog = await screen.findByRole("dialog");
    await user.click(within(dialog).getByRole("checkbox", { name: /allow upstream domain validation/i }));
    await user.click(within(dialog).getByRole("button", { name: /save/i }));

    await waitFor(() => expect(apiMock.updateACMEDNS01ProviderConfig).toHaveBeenCalled());
    const [, input] = apiMock.updateACMEDNS01ProviderConfig.mock.calls[0];
    expect(input.allow_upstream_dv).toBe(false);
  });

  // Upstream authorization freshness reaches the operator (epic B7).
  //
  // Automating DNS-01 upstream removes the human from the validation cycle, and
  // with them the human who noticed when validation broke. An authority holding a
  // valid authorization issues without a challenge, so a dead publish path stays
  // invisible until the reuse window closes — and then every identifier
  // authorized in the same original burst fails on the same day. The panel exists
  // to make that visible while it is still one warning rather than an outage.
  describe("upstream authorization freshness", () => {
    it("names the identifiers this deployment has never validated itself", async () => {
      apiMock.acmeUpstreamAuthorizations.mockResolvedValue({
        items: [
          {
            identifier: "*.app.example.test",
            issuer: "letsencrypt",
            challenge_type: "",
            last_reused_at: "2026-07-30T09:00:00Z",
            expires_at: "2026-08-09T09:00:00Z",
            reuse_count: 6,
            validate_count: 0,
            never_validated: true,
          },
          {
            identifier: "api.example.test",
            issuer: "letsencrypt",
            challenge_type: "dns-01",
            last_validated_at: "2026-08-01T10:00:00Z",
            expires_at: "2026-08-31T10:00:00Z",
            reuse_count: 0,
            validate_count: 3,
            never_validated: false,
          },
        ],
        never_validated_count: 1,
        guidance: "Rows never validated by this install are the ones to act on.",
      });

      await renderProtocols();

      const heading = await screen.findByRole("heading", { name: /upstream authorization freshness/i });
      const panel = heading.closest("section");
      expect(panel).not.toBeNull();

      // The wildcard has issued six times and proved control zero times. That is
      // the row an operator must see; reporting only "last issued" would show it
      // as the healthiest name on the list.
      expect(within(panel as HTMLElement).getByText("*.app.example.test")).toBeInTheDocument();
      expect(within(panel as HTMLElement).getByText(/never validated here/i)).toBeInTheDocument();
      // Singular, because the count is 1. "1 identifiers" is the kind of detail
      // that quietly tells a reader nobody looked at this screen.
      expect(within(panel as HTMLElement).getByText(/1 identifier has never been validated/i)).toBeInTheDocument();

      // A name that genuinely validates shows its date rather than the warning.
      // Rendered through the locale/timezone policy like every other panel in
      // this file, rather than as a raw ISO string.
      expect(within(panel as HTMLElement).getAllByText(/2026/).length).toBeGreaterThan(0);
    });

    // A failed read must not look like a healthy deployment.
    //
    // The panel hides when there is nothing to show, which is right: empty is
    // the honest answer for a deployment that never enabled upstream DV. But an
    // ERROR is a third state, and hiding it too would mean a broken surface and
    // a clean one render identically — the same false reassurance this panel
    // exists to prevent, one level up.
    it("says so when upstream freshness cannot be read at all", async () => {
      apiMock.acmeUpstreamAuthorizations.mockRejectedValue(new Error("upstream freshness offline"));
      await renderProtocols();

      expect(await screen.findByText(/upstream authorization freshness unavailable/i)).toBeInTheDocument();
      expect(screen.getByText(/nothing here should be taken as evidence that validation is healthy/i)).toBeInTheDocument();
    });

    it("stays out of the way when nothing upstream has been observed", async () => {
      await renderProtocols();
      // Empty is the honest answer for a deployment that never enabled upstream
      // DV. An empty table with a reassuring header would read as "nothing is
      // stale", which is a different and false claim.
      expect(screen.queryByRole("heading", { name: /upstream authorization freshness/i })).toBeNull();
    });
  });
});

function provider(
  name: string,
  displayName: string,
  kind: string,
  credentialReferenceFields: string[],
  capabilities: string[],
  overrides: Record<string, unknown> = {},
) {
  return {
    name,
    display_name: displayName,
    kind,
    served: true,
    propagation_preflight: true,
    conformance: "present-validate-cleanup",
    admission_state: "built-in",
    provenance: "core-build",
    credential_reference_fields: credentialReferenceFields,
    secret_fields: [],
    capabilities,
    provider_package: `internal/dns/${name}`,
    notes: "served DNS-01 provider",
    ...overrides,
  };
}

function ariPosture(overrides: Record<string, unknown> = {}) {
  return {
    served: true,
    generated_at: "2026-07-30T08:00:00Z",
    publication_status: "served",
    publication_endpoint: "/acme/renewal-info/{certid}",
    scheduler_status: "enabled",
    summary: {
      affected_certificates: 1,
      published: 1,
      scheduler_pending: 0,
      scheduler_consumed: 1,
      scheduler_failed: 0,
    },
    items: [
      {
        certificate_id: "01900000-0000-7000-8000-000000000046",
        identity_id: "01900000-0000-7000-8000-000000000047",
        identity_name: "payments-api",
        ari_certificate_id: "ari-cert-payments",
        certificate_status: "active",
        publication_status: "published",
        suggested_window: {
          start: "2026-07-30T09:00:00Z",
          end: "2026-07-31T09:00:00Z",
        },
        scheduler_status: "succeeded",
        scheduler_consumed: true,
        scheduler_source: "ari",
        rotation_run_id: "01900000-0000-7000-8000-000000000048",
        consumed_at: "2026-07-30T09:15:00Z",
      },
    ],
    ...overrides,
  };
}
