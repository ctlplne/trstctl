import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { act, cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { axe } from "vitest-axe";
import { AuthProvider } from "@/auth/AuthProvider";
import { ThemeProvider } from "@/components/ThemeProvider";
import { AppRoutes } from "@/App";
import { appRoutePaths, realGuiSurfaces } from "@/lib/navigation";

const SRC = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const REPO_ROOT = path.resolve(SRC, "..", "..");
const FEATURE_MAP_PATH = path.join(REPO_ROOT, "internal", "featureparity", "feature-map-backlog.json");
const FEATURE_A11Y_RECEIPT_REF = "web/src/__tests__/feature_a11y_receipts.test.tsx";
const allowedConsoleWarningPatterns = [/React Router Future Flag Warning:/];

type FeatureMapItem = {
  feature_id: string;
  feature: string;
  facet_evidence?: {
    a11y?: {
      evidence?: string[];
      refs?: string[];
      na?: string;
    };
    ui?: {
      evidence?: string[];
      na?: string;
    };
  };
};

type FeatureMapBacklog = {
  items: FeatureMapItem[];
};

const shellOnlyA11yPattern = /\b(?:primary navigation|registered customer routes|keyboard traversal|mobile drawer|skip link|shell accessibility|app shell)\b/i;
const originalConsoleError = console.error.bind(console);

type RestorableSpy = { mockRestore: () => void };

let consoleErrorSpy: RestorableSpy | undefined;
let consoleWarnSpy: RestorableSpy | undefined;
let unexpectedConsoleMessages: string[] = [];

function formatConsoleMessage(args: unknown[]): string {
  return args
    .map((arg) => {
      if (arg instanceof Error) return arg.stack ?? arg.message;
      if (typeof arg === "string") return arg;
      try {
        return JSON.stringify(arg) ?? String(arg);
      } catch {
        return String(arg);
      }
    })
    .join(" ");
}

function installConsoleWarningGuard() {
  unexpectedConsoleMessages = [];
  consoleErrorSpy = vi.spyOn(console, "error").mockImplementation((...args: unknown[]) => {
    const message = formatConsoleMessage(args);
    if (allowedConsoleWarningPatterns.some((pattern) => pattern.test(message))) return;
    unexpectedConsoleMessages.push(`console.error: ${message}`);
  });
  consoleWarnSpy = vi.spyOn(console, "warn").mockImplementation((...args: unknown[]) => {
    const message = formatConsoleMessage(args);
    if (allowedConsoleWarningPatterns.some((pattern) => pattern.test(message))) return;
    unexpectedConsoleMessages.push(`console.warn: ${message}`);
  });
}

function restoreConsoleWarningGuard() {
  consoleErrorSpy?.mockRestore();
  consoleWarnSpy?.mockRestore();
  consoleErrorSpy = undefined;
  consoleWarnSpy = undefined;
}

function assertNoUnexpectedConsoleWarnings() {
  if (unexpectedConsoleMessages.length === 0) return;
  originalConsoleError(unexpectedConsoleMessages.join("\n\n"));
  expect(unexpectedConsoleMessages).toEqual([]);
}

async function waitForRouteEffectsToSettle() {
  await act(async () => {
    for (let pass = 0; pass < 8; pass += 1) {
      resolvePendingApiResponses();
      await Promise.resolve();
      // TanStack Query batches observer notifications on a zero-delay timer.
      // Drain that queue inside act before deciding the route is settled.
      await new Promise((resolve) => setTimeout(resolve, 0));
    }
  });
}

const { apiMock, resolvePendingApiResponses } = vi.hoisted(() => {
  const store: Record<string, ReturnType<typeof vi.fn>> = {};
  const pendingApiResolvers: Array<() => void> = [];

  function valueFor(name: string): unknown {
    switch (name) {
      case "me":
        return {
          subject: "operator",
          tenant_id: "tenant-1",
          email: "operator@example.test",
          permissions: ["*"],
        };
      case "certificatePage":
        return { items: [{ id: "cert-1", subject: "api.example.test", status: "active", fingerprint: "SHA256:abc" }] };
      case "certificates":
        return [{ id: "cert-1", subject: "api.example.test", status: "active", fingerprint: "SHA256:abc" }];
      case "identities":
        return [{ id: "id-1", name: "payments-api", kind: "workload_identity", status: "issued", tenant_id: "tenant-1" }];
      case "approvalRequests":
        return [];
      case "risk":
        return [{ id: "risk-1", credential_id: "risk-1", subject: "payments-api", kind: "workload_identity", score: 91, level: "high", owner: "platform" }];
      case "contextualRiskPriorities":
        return {
          summary: {
            priorities: 0,
            total_analyzed: 0,
            high_blast_radius: 0,
            weak_crypto_context: 0,
            critical: 0,
            high: 0,
            medium: 0,
          },
          priorities: [],
        };
      case "nhiPolicyCompliance":
        return {
          summary: {
            violations: 0,
            total_analyzed: 0,
            rotation_violations: 0,
            scope_violations: 0,
            geo_violations: 0,
            expiry_violations: 0,
            business_purpose_missing: 0,
            critical: 0,
            high: 0,
            medium: 0,
          },
          findings: [],
        };
      case "nhiOverPrivilegePosture":
        return {
          summary: {
            overprivileged: 0,
            total_analyzed: 0,
            unused_grants: 0,
            critical: 0,
            high: 0,
          },
          findings: [],
        };
      case "nhiStalePosture":
        return {
          summary: {
            findings: 0,
            total_analyzed: 0,
            dormant: 0,
            orphaned: 0,
            critical: 0,
            high: 0,
            medium: 0,
          },
          findings: [],
        };
      case "nhiStaticPosture":
        return {
          summary: {
            findings: 0,
            total_analyzed: 0,
            long_lived: 0,
            static_credentials: 0,
            critical: 0,
            high: 0,
            medium: 0,
          },
          findings: [],
        };
      case "nhiExposurePosture":
        return {
          summary: {
            findings: 0,
            total_analyzed: 0,
            internet_exposed: 0,
            weak_authentication: 0,
            insecure_transport: 0,
            critical: 0,
            high: 0,
            medium: 0,
          },
          findings: [],
        };
      case "owners":
      case "issuers":
      case "externalCAs":
      case "agents":
      case "profiles":
        return [];
      case "rotationRuns":
      case "connectorDeliveries":
      case "connectorTargets":
      case "discoverySources":
      case "discoverySchedules":
      case "discoveryRuns":
      case "discoveryFindings":
      case "incidentExecutions":
      case "fleetReissuanceRuns":
      case "remediationPlaybookRuns":
      case "notifications":
      case "notificationChannels":
      case "notificationRoutingPolicies":
      case "complianceReportSchedules":
      case "nhiReviewCampaigns":
      case "accessChangeRequests":
      case "policyVersions":
      case "privacySubjectErasures":
      case "privacyRetentionRuns":
      case "apiTokens":
        return { items: [] };
      case "connectorCatalog":
        return { connectors: [], items: [] };
      case "secretPage":
        return { items: [] };
      case "secretRepositoryScanning":
        return {
          capability: "CAP-SCAN-01",
          served: true,
          generated_at: "2026-07-02T00:00:00Z",
          scanner: "gitleaks",
          minimum_rules_active: 0,
          providers: [],
          webhook_paths: [],
          queue_model: "fixture",
          redaction_model: "metadata only",
          event_flow: [],
          release_gates: [],
          operator_actions: [],
          residuals: [],
          evidence_refs: [],
          architecture_controls: [],
        };
      case "thirdPartySecretScanning":
        return {
          capability: "CAP-SCAN-04",
          served: true,
          generated_at: "2026-07-02T00:00:00Z",
          scanner: "gitleaks",
          minimum_rules_active: 0,
          providers: [],
          ingest_paths: [],
          queue_model: "fixture",
          redaction_model: "metadata only",
          event_flow: [],
          release_gates: [],
          operator_actions: [],
          residuals: [],
          evidence_refs: [],
          architecture_controls: [],
        };
      case "cloudSecretManagers":
        return {
          capability: "CAP-SEC-04",
          served: true,
          generated_at: "2026-07-02T00:00:00Z",
          summary: {
            total_providers: 0,
            discovery_supported: 0,
            discovery_configured: 0,
            sync_supported: 0,
            sync_configured: 0,
            fully_configured: 0,
            configured_connections: 0,
          },
          configured_providers: [],
          configured_sync_targets: [],
          discovery_mode: "fixture",
          outbox_mode: "fixture",
          secret_handling: "metadata only",
          architecture_controls: [],
          evidence_refs: [],
          residuals: [],
          recommended_next_actions: [],
          providers: [],
        };
      case "secretSyncTargets":
        return {
          capability: "CAP-SECR-03",
          served: true,
          generated_at: "2026-07-02T00:00:00Z",
          configured_targets: [],
          outbox_mode: "fixture",
          evidence_refs: [],
          residuals: [],
          targets: [],
        };
      case "kubernetesSecretOperator":
        return {
          capability: "CAP-SECR-04",
          served: true,
          generated_at: "2026-07-02T00:00:00Z",
          crds: [],
          sync_flow: [],
          reload_workloads: [],
          secret_handling: "metadata only",
          architecture_controls: [],
          evidence_refs: [],
          residuals: [],
          recommended_next_actions: [],
        };
      case "secretWorkloadInjection":
        return {
          capability: "CAP-SECR-05",
          served: true,
          generated_at: "2026-07-02T00:00:00Z",
          crd: {
            kind: "TrstctlSecretInjection",
            api_group: "trstctl.com",
            api_version: "trstctl.com/v1alpha1",
            plural: "trstctlsecretinjections",
            status: "served",
            owns: [],
            evidence_ref: "",
          },
          modes: [],
          workload_kinds: [],
          sidecar_command: [],
          annotations: [],
          sync_dependency: "TrstctlSecretSync",
          secret_handling: "metadata only",
          architecture_controls: [],
          evidence_refs: [],
          residuals: [],
          recommended_next_actions: [],
        };
      case "unvaultedSecrets":
        return {
          capability: "CAP-SECR-07",
          served: true,
          generated_at: "2026-07-02T00:00:00Z",
          summary: {
            repository_sources: 0,
            third_party_sources: 0,
            cloud_secret_sources: 0,
            vault_providers_supported: 0,
            vault_providers_visible: 0,
            sync_targets_configured: 0,
            leaked_secret_findings: 0,
          },
          detection_sources: [],
          vault_providers: [],
          configured_vaults: [],
          configured_sync_targets: [],
          workflow: [],
          secret_handling: "metadata only",
          architecture_controls: [],
          evidence_refs: [],
          residuals: [],
          recommended_next_actions: [],
        };
      case "protocolStatuses":
        return { source: "test", checked_at: "2026-07-02T00:00:00Z", items: [] };
      case "acmeDNS01Providers":
        return { providers: [] };
      case "acmeDNS01ProviderConfigs":
        return { items: [] };
      case "mdmSCEPStatus":
        return {
          policies: [],
          telemetry: { allowed: 0, denied: 0, replay_rejected: 0 },
          runtime_gate: false,
          runtime_note: "not configured in fixture",
        };
      case "aiStatus":
        return { enabled: false, mode: "disabled", model: "", endpoint_host: "", egress_mode: "off" };
      case "mcpTools":
        return { tools: [] };
      case "accessRoles":
        return { items: [] };
      case "oidcMappingStatus":
        return { enabled: false, tenant_mappings: [] };
      case "members":
        return { items: [] };
      case "editions":
        return { tier: "community", state: "community", features: [], fips: { module_active: false, required: false, self_test_passed: true } };
      case "enterpriseSupportStatus":
        return { served: true, support_tiers: [], sla_targets: [], professional_services: [] };
      case "managedOfferingStatus":
        return { served: true, deployment_model: "self_hosted", provider_plane_mode: "off" };
      case "scaleOrchestration":
        return { capability: "CAP-SCALE-01", served: true, target_credential_bands: [], execution_lanes: [], release_gates: [] };
      case "activeActiveIssuance":
        return { capability: "CAP-SCALE-02", served: true, regions: [], tenant_write_fences: [], release_gates: [] };
      case "caDiscoveryInventory":
        return {
          items: [],
          summary: {
            public_count: 0,
            private_count: 0,
            external_registry_count: 0,
            authority_count: 0,
          },
        };
      case "certificateHealth":
        return {
          summary: {
            health: "ok",
            total: 1,
            expiring_7d: 0,
            expiring_30d: 0,
            external_source_count: 0,
          },
          source_breakdown: [],
          expiring: [],
        };
      case "crlDistributions":
        return { items: [] };
      case "rogueCertificates":
        return {
          summary: {
            findings: 0,
            rogue: 0,
            non_compliant: 0,
            ct_unexpected: 0,
            critical: 0,
            high: 0,
          },
          findings: [],
        };
      case "discoveryMonitoring":
        return { summary: {}, sources: [] };
      case "discoveryCoverage":
        return { generated_at: "2026-06-20T10:05:00Z", observed: 0, unobserved: 0, structurally_unobservable: 0, classes: [] };
      case "nhiShadowPosture":
        return {
          summary: {
            findings: 0,
            unmanaged: 0,
            unregistered: 0,
            ownerless: 0,
            high: 0,
            critical: 0,
            total_analyzed: 0,
            kind_counts: {},
            surface_counts: {},
          },
          capability: "nhi.shadow",
          findings: [],
        };
      case "ctMonitoring":
        return {
          capability: "F17",
          watched_domains: [],
          logs: [],
          summary: {
            source_count: 0,
            watched_domain_count: 0,
            log_count: 0,
            finding_count: 0,
            unexpected_issuance_count: 0,
            open_finding_count: 0,
            outbox_alert_channel_count: 0,
          },
          findings: [],
          outbox_backed_alerts: true,
        };
      case "driftRemediation":
        return {
          capability: "F18",
          dashboard_path: "/api/v1/discovery/drift-remediation",
          sources_path: "/api/v1/discovery/sources",
          runs_path: "/api/v1/discovery/runs",
          findings_path: "/api/v1/discovery/findings",
          summary: {
            source_count: 0,
            finding_count: 0,
            open_finding_count: 0,
            investigating_count: 0,
            remediated_count: 0,
            dismissed_count: 0,
            remediation_decision_count: 0,
            deleted_count: 0,
            replaced_count: 0,
            relocated_count: 0,
            permission_changed_count: 0,
            certificate_count: 0,
            ssh_key_count: 0,
            secret_count: 0,
          },
          findings: [],
        };
      case "listCBOMAssets":
        return {
          migration_progress: {
            total_assets: 0,
            out_of_policy_assets: 0,
            quantum_vulnerable_assets: 0,
            post_quantum_ready_assets: 0,
            percent_migrated: 0,
          },
          items: [],
        };
      case "pqcCampaigns":
        return {
          items: [],
          next_cursor: "",
        };
      case "complianceEvidencePack":
        return {
          format: "trstctl.compliance.evidence-pack.v3",
          framework: "soc2",
          public_key_der: "BASE64PUBLICKEY",
          custody: {
            total: 0,
            recorded: 0,
            unrecorded: 0,
            origins: { requester: 0, host_agent: 0, device: 0, control_plane: 0, signer: 0 },
            storage: { locked_memory: 0, file: 0, os_store: 0, pkcs11: 0, device_bound: 0, service: 0 },
            exportability: { exportable: 0, non_exportable: 0 },
            unrecorded_certificates: [],
          },
          signed_export: {
            manifest: {
              framework: "soc2",
              controls: [],
              posture: { total_crypto_assets: 0, quantum_vulnerable: 0, post_quantum: 0 },
              custody: {
                total: 0,
                recorded: 0,
                unrecorded: 0,
                origins: { requester: 0, host_agent: 0, device: 0, control_plane: 0, signer: 0 },
                storage: { locked_memory: 0, file: 0, os_store: 0, pkcs11: 0, device_bound: 0, service: 0 },
                exportability: { exportable: 0, non_exportable: 0 },
                unrecorded_certificates: [],
              },
              product_evidences: [],
              operator_attests: [],
            },
            signature: "signed-by-export-key",
          },
        };
      case "complianceInventoryReport":
        return {
          capability: "CAP-OBS-02",
          generated_at: "2026-07-02T00:00:00Z",
          frameworks: [],
          report_types: [],
          routes: [],
          evidence_refs: [],
          schedules: [],
          summary: {
            certificates: 0,
            crypto_assets: 0,
            discovery_schedules: 0,
            report_schedules: 0,
            enabled_report_schedules: 0,
            frameworks_supported: 0,
            report_types_supported: 0,
            inventory_rows: 0,
          },
        };
      case "nhiComplianceReport":
        return {
          format: "trstctl.nhi.compliance-report.v1",
          capability: "CAP-CMP-06",
          generated_at: "2026-07-02T00:00:00Z",
          audit_ready: true,
          summary: {
            total_nhis: 0,
            inventory_kinds: 0,
            frameworks_supported: 0,
            controls_mapped: 0,
            overprivileged_findings: 0,
            stale_findings: 0,
            static_credential_findings: 0,
            audit_evidence_refs: 0,
            operator_attestation_needed: 0,
          },
          frameworks: [],
          controls: [],
          report_types: [],
          routes: [],
          evidence_refs: [],
          residuals: [],
        };
      case "privacyCatalog":
        return { items: [] };
      case "auditEvents":
        return [];
      case "graph":
        return { nodes: [], edges: [] };
      case "graphBlastRadius":
      case "graphReachable":
        return { nodes: [], edges: [] };
      case "remediationPlaybooks":
        return { capability: "CAP-REM-01", status: "served", generated_at: "2026-07-02T00:00:00Z", items: [] };
      case "ownerRemediationActions":
        return {
          capability: "CAP-REM-02",
          status: "served",
          generated_at: "2026-07-02T00:00:00Z",
          summary: { total: 0, open: 0, accepted: 0, critical: 0, high: 0, medium: 0, low: 0 },
          items: [],
          evidence_refs: [],
        };
      case "workloadAttesterTrustSources":
        return { items: [] };
      case "sshStatus":
        return { authorities: [], trust_rollouts: [] };
      case "platformSystem":
        // The custody/idempotency panels index the readout's typed state; the
        // generic {} default crashed them (COVER-005 Platform-route fix).
        return {
          version: "dev",
          commit: "0000000",
          build_date: "2026-06-20T00:00:00Z",
          go_version: "go1.25",
          started_at: "2026-06-20T00:00:00Z",
          uptime_seconds: 60,
          signer_mode: "child",
          fips_module_active: false,
          dependencies: [],
          idempotency_results: {
            state: "complete",
            fleet_ready: true,
            sealed_only_floor: true,
            sealed_results: 1,
            pending_results: 0,
            indeterminate_results: 0,
            legacy_dynamic_remaining: 0,
            raw_v0_remaining: 0,
            recovery: "No recovery action is required.",
          },
        };
      case "tenantKeyDomain":
        return {
          served: true,
          state: "unsealed",
          protection_mode: "local",
          recovery: "Wrapper material is recoverable from the local KEK file.",
          remote_wrapper_state: "not-configured",
          legacy_history_exposure: "none",
          local_wrapper_zero_egress: true,
          retryable: false,
          progress_completed: 0,
          progress_total: 0,
          last_transition_evidence_refs: [],
        };
      default:
        return {};
    }
  }

  const apiMock = new Proxy(store, {
    get(target, prop: string) {
      if (!(prop in target)) {
        target[prop] = vi.fn(
          () =>
            new Promise((resolve) => {
              pendingApiResolvers.push(() => resolve(valueFor(prop)));
            }),
        );
      }
      return target[prop];
    },
  });

  function resolvePendingApiResponses() {
    const resolvers = pendingApiResolvers.splice(0);
    resolvers.forEach((resolve) => resolve());
  }

  return { apiMock, resolvePendingApiResponses };
});

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: apiMock };
});

function featureMap(): FeatureMapBacklog {
  return JSON.parse(readFileSync(FEATURE_MAP_PATH, "utf8")) as FeatureMapBacklog;
}

function renderRoute(route: string) {
  return render(
    <ThemeProvider>
      <AuthProvider>
        <MemoryRouter initialEntries={[route]}>
          <AppRoutes />
        </MemoryRouter>
      </AuthProvider>
    </ThemeProvider>,
  );
}

function basePath(route: string): string {
  return route.split("?")[0] || "/";
}

describe("COVER-005 feature-specific a11y receipts", () => {
  beforeEach(() => {
    Object.values(apiMock).forEach((mock) => mock.mockClear());
    localStorage.clear();
    Object.defineProperty(window, "innerWidth", { configurable: true, value: 1180, writable: true });
    installConsoleWarningGuard();
  });

  afterEach(async () => {
    try {
      cleanup();
      await waitForRouteEffectsToSettle();
      assertNoUnexpectedConsoleWarnings();
    } finally {
      restoreConsoleWarningGuard();
    }
  });

  it("requires UI feature rows to cite this feature-specific a11y receipt instead of shell-only proof", () => {
    const map = featureMap();
    const surfaceFeatureIds = new Set(realGuiSurfaces.map((surface) => surface.featureId));

    for (const item of map.items) {
      const uiEvidence = item.facet_evidence?.ui?.evidence ?? [];
      const uiNA = item.facet_evidence?.ui?.na ?? "";
      if (uiEvidence.length === 0 || uiNA) continue;

      const a11y = item.facet_evidence?.a11y;
      expect(a11y?.na ?? "", `${item.feature_id} ${item.feature} must not mark UI a11y N/A`).toBe("");

      if (surfaceFeatureIds.has(item.feature_id)) {
        expect(a11y?.refs ?? [], `${item.feature_id} ${item.feature} must cite the feature-specific a11y receipt`).toContain(FEATURE_A11Y_RECEIPT_REF);
        expect((a11y?.evidence ?? []).join(" "), `${item.feature_id} ${item.feature} must not rely on shell-only a11y text`).not.toMatch(shellOnlyA11yPattern);
        continue;
      }

      expect(item.feature_id, `${item.feature_id} ${item.feature} lacks a real GUI surface; only F12 may use shell-level proof`).toBe("F12");
      expect((a11y?.evidence ?? []).join(" ")).toMatch(/navigation-shell/i);
    }
  });

  it("runs axe and keyboard smoke receipts against each route-backed feature surface", async () => {
    const routeFeatureIds = new Map<string, Set<string>>();
    for (const surface of realGuiSurfaces) {
      for (const route of surface.routes) {
        const path = basePath(route);
        expect(appRoutePaths).toContain(path as (typeof appRoutePaths)[number]);
        if (!routeFeatureIds.has(path)) routeFeatureIds.set(path, new Set());
        routeFeatureIds.get(path)?.add(surface.featureId);
      }
    }

    for (const [route, featureIds] of routeFeatureIds) {
      cleanup();
      const user = userEvent.setup();
      const { container } = renderRoute(route);
      await waitForRouteEffectsToSettle();
      const main = await screen.findByRole("main");
      await waitForRouteEffectsToSettle();

      // S-C3: pages are lazy chunks — wait for the surface (its first heading)
      // to replace the Suspense fallback before running the receipts.
      await within(main).findAllByRole("heading");
      expect(within(main).getAllByRole("heading").length, `${route} should expose feature headings for ${[...featureIds].join(",")}`).toBeGreaterThan(0);
      expect(await axe(container), `${route} axe receipt for ${[...featureIds].join(",")}`).toHaveNoViolations();
      await waitForRouteEffectsToSettle();

      await user.tab();
      await waitForRouteEffectsToSettle();
      await waitFor(() => expect(document.activeElement, `${route} should expose keyboard focus`).not.toBe(document.body));
    }
  }, 30_000);
});
