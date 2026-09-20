// SPDX-License-Identifier: BUSL-1.1

package docs

// TRACE completeness-track guards (audit remediation: TRACE-002..008, TRACE-011).
//
// These are OMISSION/OVERCLAIM guards. Each capability below is partially built but
// NOT served as a complete end-to-end control-plane workflow; the honest disclosure
// in docs/limitations.md (and in-product copy) says exactly which slice is served
// and which is library/API-only. The risk is that a future change either (a) starts
// serving the missing slice but leaves the stale "not served" disclosure, or (b)
// removes/over-claims the disclosure while the code is still library-only. Each guard
// binds the disclosure to a code anchor IN BOTH DIRECTIONS so neither can drift
// silently. The guard going red when the disclosure is removed (or the served-vs-
// library reality flips without the docs being updated) is the fail-before/pass-after
// proof for these completeness gaps.
//
// Style note: these reuse the docs-package helpers read(), containsAll(), and
// nonTestGoFiles() (defined in docs_test.go), and the served-vs-library import-scan
// idiom — exactly the pattern of TestServedVsLibraryStatusIsHonestAndCodeBound.

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

// importsAnyOnServedPath reports whether any non-test Go file under the served
// composition dirs (api, server, cmd/trstctl) imports any of the given fully
// qualified import paths. This is the canonical "is it wired into the running
// binary?" probe used across the served-vs-library guards.
func importsAnyOnServedPath(t *testing.T, imports ...string) bool {
	t.Helper()
	for _, dir := range []string{"../internal/api", "../internal/server", "../cmd/trstctl"} {
		for _, f := range nonTestGoFiles(t, dir) {
			src := read(t, f)
			for _, imp := range imports {
				if strings.Contains(src, imp) {
					return true
				}
			}
		}
	}
	return false
}

// limLower returns docs/limitations.md lowercased with whitespace collapsed, so a
// marker that the Markdown source wraps across lines still matches.
func limLower(t *testing.T) string {
	t.Helper()
	return strings.Join(strings.Fields(strings.ToLower(read(t, "limitations.md"))), " ")
}

// ---- TRACE-002: discovery control plane + network/cloud/CT/drift/SSH host-key
//      execution served ---------------------------------------------------------

// networkScanExecutorServed reports whether the served binary actually executes a
// network discovery scan: the outbox-dispatched worker in internal/server imports
// the netscan collector AND runs it. This is the served increment that distinguishes
// TRACE-002 from a pure intent-only control plane.
func networkScanExecutorServed(t *testing.T) bool {
	t.Helper()
	if !importsAnyOnServedPath(t, `trstctl.com/trstctl/internal/discovery/netscan"`) {
		return false
	}
	// The import alone is not enough — confirm the served worker invokes the scanner.
	disc := read(t, "../internal/server/discovery.go")
	return strings.Contains(disc, "netscan.New(") && strings.Contains(disc, ".Scan(")
}

func cloudCertExecutorServed(t *testing.T) bool {
	t.Helper()
	disc := read(t, "../internal/server/discovery.go")
	return importsAnyOnServedPath(t, `trstctl.com/trstctl/internal/discovery/cloudcert"`) &&
		strings.Contains(disc, "executeCloudCertificateDiscoveryRun") &&
		strings.Contains(disc, "cloudcert.NewDiscoverer")
}

func ctMonitorExecutorServed(t *testing.T) bool {
	t.Helper()
	disc := read(t, "../internal/server/discovery.go")
	return importsAnyOnServedPath(t, `trstctl.com/trstctl/internal/discovery/ctmonitor"`) &&
		strings.Contains(disc, "executeCTLogDiscoveryRun") &&
		strings.Contains(disc, "ctmonitor.NewScheduler")
}

func driftExecutorServed(t *testing.T) bool {
	t.Helper()
	disc := read(t, "../internal/server/discovery.go")
	return importsAnyOnServedPath(t, `trstctl.com/trstctl/internal/agent/drift"`) &&
		strings.Contains(disc, "executeDriftDiscoveryRun") &&
		strings.Contains(disc, "drift.Reconciler")
}

func sshCollectorServed(t *testing.T) bool {
	t.Helper()
	// SSH targets are deliberately relay-owned: the control-plane server stamps the
	// command but must not import or dial sshscan itself. Bind both halves of the
	// shipped path so a library-only scanner and an intent-only server both fail.
	relay := read(t, "../internal/agent/relay/discoveryscan.go")
	server := read(t, "../internal/server/discovery.go")
	return strings.Contains(relay, `trstctl.com/trstctl/internal/discovery/sshscan"`) &&
		strings.Contains(relay, "sshscan.New(") &&
		strings.Contains(server, `"ssh":               (*issuanceDispatcher).executeRelayOwnedDiscoveryRun`) &&
		strings.Contains(server, `source.Kind == "network" || source.Kind == "ssh"`)
}

// TestDiscoveryServedControlPlaneAndNetworkScanVsLibraryCollectorsIsHonest pins
// TRACE-002. The running binary serves the discovery control/scheduling API AND
// executes real network, SSH host-key, cloud-certificate, CT-log, and drift scans
// end-to-end via the outbox worker. The disclosure must state the served halves
// honestly and not keep stale library-only caveats after a collector is wired.
func TestDiscoveryServedControlPlaneAndNetworkScanVsLibraryCollectorsIsHonest(t *testing.T) {
	low := limLower(t)

	// Reality anchor (served control plane): the discovery control routes are mounted
	// and queue runs.
	apiRoutes := read(t, "../internal/api/api.go")
	for _, route := range []string{`path: "/api/v1/discovery/sources"`, `path: "/api/v1/discovery/runs"`} {
		if !strings.Contains(apiRoutes, route) {
			t.Fatalf("internal/api/api.go no longer registers %s; the TRACE-002 served-discovery-control disclosure has no code anchor — revisit this reality test", route)
		}
	}
	if !strings.Contains(read(t, "../internal/api/discovery.go"), "QueueDiscoveryRun") {
		t.Fatal("internal/api/discovery.go no longer queues discovery runs; the TRACE-002 served-control disclosure has no code anchor — revisit this reality test")
	}
	// Reality anchor (library side): collector packages still exist, so status claims
	// about served/unserved execution are grounded.
	for _, pkg := range []string{"sshscan", "cloudcert", "ctmonitor"} {
		if _, err := os.Stat("../internal/discovery/" + pkg); err != nil {
			t.Fatalf("internal/discovery/%s no longer exists; revisit this TRACE-002 reality test", pkg)
		}
	}
	if _, err := os.Stat("../internal/agent/drift"); err != nil {
		t.Fatalf("internal/agent/drift no longer exists; revisit this TRACE-002 reality test: %v", err)
	}

	// The disclosure must always state the served control-plane half.
	for _, m := range []string{"/api/v1/discovery/*", "discovery control plane"} {
		if !strings.Contains(low, m) {
			t.Errorf("limitations.md must disclose the served discovery control plane (missing marker %q) — TRACE-002", m)
		}
	}

	// Served-network-scan half: bind it to the worker reality in both directions.
	if networkScanExecutorServed(t) {
		if !strings.Contains(low, "network scan execution") {
			t.Error("the served binary executes network discovery scans (netscan via the outbox worker) but limitations.md does not disclose served network scan execution — TRACE-002")
		}
	} else {
		// Regression: netscan no longer runs on the served path. The "network scan
		// execution" served claim must not remain.
		if strings.Contains(low, "network scan execution") {
			t.Error("limitations.md claims served network scan execution but internal/server/discovery.go no longer runs netscan on the served path — TRACE-002 regression")
		}
	}

	if cloudCertExecutorServed(t) {
		if !strings.Contains(low, "cloud-certificate discovery execution") {
			t.Error("the served binary executes cloud-certificate discovery but limitations.md does not disclose cloud-certificate discovery execution — TRACE-002")
		}
	} else if strings.Contains(low, "cloud-certificate discovery execution") {
		t.Error("limitations.md claims cloud-certificate discovery execution but the served worker no longer imports and invokes cloudcert — TRACE-002 regression")
	}

	if ctMonitorExecutorServed(t) {
		if !containsAll(low, []string{"ct-log", "drift execution"}) {
			t.Error("the served binary executes CT-log discovery but limitations.md does not disclose CT-log discovery execution — TRACE-002")
		}
		if containsAll(low, []string{"certificate transparency", "no path into the served worker"}) {
			t.Error("CT monitoring is now wired into the served worker, but limitations.md still says Certificate Transparency has no served worker path — TRACE-002")
		}
	} else if strings.Contains(low, "ct-log") && strings.Contains(low, "served discovery worker") {
		t.Error("limitations.md claims CT-log discovery execution but the served worker no longer imports and invokes ctmonitor — TRACE-002 regression")
	}

	if driftExecutorServed(t) {
		if !containsAll(low, []string{"drift", "served discovery worker"}) {
			t.Error("the served binary executes credential drift detection but limitations.md does not disclose drift execution through the served worker — TRACE-002")
		}
	} else if strings.Contains(low, "drift") && strings.Contains(low, "served discovery worker") {
		t.Error("limitations.md claims drift execution but the served worker no longer imports and invokes internal/agent/drift — TRACE-002 regression")
	}

	// SSH host-key execution is now served through the discovery outbox worker.
	if sshCollectorServed(t) {
		if !containsAll(low, []string{"ssh host-key", "discovery outbox worker"}) {
			t.Error("the served binary executes SSH host-key discovery but limitations.md does not disclose the served SSH host-key discovery worker path — TRACE-002")
		}
		if containsAll(low, []string{"ssh key/trust scan", "no path into the served worker"}) {
			t.Error("SSH discovery execution is now wired into the served worker, but limitations.md still says SSH has no served worker path — update the disclosure (TRACE-002)")
		}
		return
	}
	for _, m := range []string{"ssh key/trust scan", "no path into the served worker"} {
		if !strings.Contains(low, m) {
			t.Errorf("limitations.md must disclose the SSH discovery collector as library/agent-owned (missing marker %q) — TRACE-002", m)
		}
	}
	for _, oc := range []string{
		"all discovery scans are served",
		"ssh discovery execution is served",
	} {
		if strings.Contains(low, oc) {
			t.Errorf("limitations.md over-claims an unserved discovery collector as served (%q) — TRACE-002", oc)
		}
	}
}

// ---- TRACE-003: managed-key (BYOK/HSM) package path versus DoD-served custody --

// TestManagedKeyLifecycleServedAndRemainingCustodyGapIsHonest keeps the TRACE-003
// source and disclosure anchors cheap and deterministic. The full unfocused
// tools/dodcensus run binds these words to fresh production assembly and runtime
// evidence before make dod-gate can pass.
func TestManagedKeyLifecycleServedAndRemainingCustodyGapIsHonest(t *testing.T) {
	low := strings.Join(strings.Fields(limLower(t)), " ")

	// Reality anchor (served side): the managed-key routes are registered by the
	// served API and the service exists.
	apiRoutes := read(t, "../internal/api/api.go")
	for _, route := range []string{`path: "/api/v1/managed-keys"`, `path: "/api/v1/managed-keys/rotate"`} {
		if !strings.Contains(apiRoutes, route) {
			t.Fatalf("internal/api/api.go no longer registers %s; the TRACE-003 served-managed-key disclosure has no code anchor — revisit this reality test", route)
		}
	}
	if _, err := os.Stat("../ee/managedkeys"); err != nil {
		t.Fatalf("ee/managedkeys no longer exists; revisit this TRACE-003 reality test: %v", err)
	}
	// Reality anchor (library side): the in-process BYOK lifecycle the residual gap
	// rests on still exists.
	if _, err := os.Stat("../internal/crypto/byok"); err != nil {
		t.Fatalf("internal/crypto/byok no longer exists; the TRACE-003 in-process-BYOK residual disclosure has no code anchor — revisit this reality test: %v", err)
	}

	for _, marker := range []string{
		"six of six backends served",
		"control-plane process does not construct a provider",
		"postgresql outbox",
		"fsync-backed journal",
		"high-fidelity protocol emulation",
	} {
		if !strings.Contains(low, marker) {
			t.Errorf("limitations.md must describe the served HSM/KMS custody spine (missing %q) — TRACE-003", marker)
		}
	}
}

// ---- TRACE-004: deployment connectors — served native delivery spine -----------

// TestConnectorDeliveryServedVsLibraryMutationIsHonest pins TRACE-004. The connector
// catalog, target metadata, outbox intent, receipts, signed-WASM dispatch, and native
// implementation set are production-assembled. Native delivery remains conditional
// on an operator selecting a connector and supplying its target policy/credentials;
// a test that injects ConnectorRegistry does not change that boundary.
func TestConnectorDeliveryServedVsLibraryMutationIsHonest(t *testing.T) {
	low := limLower(t)

	// Reality anchor (served side): the connector catalog + delivery routes are
	// registered and the served catalog exists in code.
	apiRoutes := read(t, "../internal/api/api.go")
	for _, route := range []string{`path: "/api/v1/connectors/catalog"`, `path: "/api/v1/connectors/deliveries"`} {
		if !strings.Contains(apiRoutes, route) {
			t.Fatalf("internal/api/api.go no longer registers %s; the TRACE-004 served-connector disclosure has no code anchor — revisit this reality test", route)
		}
	}
	if !strings.Contains(read(t, "../internal/api/connectors_lifecycle.go"), "servedConnectorCatalog") {
		t.Fatal("internal/api/connectors_lifecycle.go no longer defines servedConnectorCatalog; the TRACE-004 served-catalog disclosure has no code anchor — revisit this reality test")
	}
	// Reality anchor (consumer side): the native registry seam and dispatcher exist.
	// Production construction is governed by the DoD census capability mapping below.
	serverBuild := read(t, "../internal/server/server.go")
	if !strings.Contains(serverBuild, "ConnectorRegistry *connector.Registry") {
		t.Fatal("server.Deps no longer exposes ConnectorRegistry; the TRACE-004 native served path lost its composition anchor")
	}
	dispatcher := read(t, "../internal/server/issuance.go")
	for _, marker := range []string{"connectorRegistry.Deploy", "native_delivered", "native_payload_missing_credential"} {
		if !strings.Contains(dispatcher, marker) {
			t.Fatalf("internal/server/issuance.go missing %q; the TRACE-004 native deploy receipt path regressed", marker)
		}
	}
	// Reality anchor (connector side): the connector implementation bodies still exist.
	if _, err := os.Stat("../internal/connector"); err != nil {
		t.Fatalf("internal/connector no longer exists; revisit this TRACE-004 reality test: %v", err)
	}

	connectorState := featureMapServedState{}
	for _, item := range featureServedStateLedger(t).Items {
		if item.FeatureID == "F7" {
			connectorState = item
			break
		}
	}
	if connectorState.ServedState != "conditional" || !containsString(connectorState.DoDCapabilities, "connector") {
		t.Fatalf("F7 native connectors must stay operator-conditional and census-bound, got state=%q capabilities=%v", connectorState.ServedState, connectorState.DoDCapabilities)
	}

	// The served catalog/receipts half and operator-conditional native delivery must
	// both be stated.
	if !strings.Contains(low, "connector.delivery.recorded") {
		t.Error("limitations.md must disclose that the binary serves the connector catalog and delivery receipts — TRACE-004")
	}
	if !containsAll(low, []string{"deployment connector orchestration", "all 24 advertised", "native connectors", "buildrundeps", "durable outbox", "provider-specific mutation", "independent external readback"}) {
		t.Error("limitations.md must disclose the served orchestration/native-delivery spine and its operator-conditional boundary — TRACE-004")
	}
	for _, stale := range []string{
		"actual target mutation is routed only when a provenance-verified signed connector plugin is loaded",
		"without live deploy",
		"deployment connector implementation bodies",
	} {
		if strings.Contains(low, stale) {
			t.Errorf("limitations.md still contains stale connector limitation wording %q — TRACE-004", stale)
		}
	}
}

// ---- TRACE-005: secrets expansion (ephemeral keys, scanning triage, dynamic
//      secrets, transit/KMIP, secret-sync) — disclosed at the right served state ----

// TestSecretsExpansionDisclosedLibraryOnlyInProductAndDocs pins TRACE-005. The web
// console honestly labels the not-yet-served secrets surfaces as library-only/
// unavailable, labels dynamic leases and ephemeral API keys as served, and
// limitations.md discloses secret-sync and transit/KMIP at their current served
// state. This binds the in-product disclosure to the web source and the docs
// disclosure to the code reality.
func TestSecretsExpansionDisclosedLibraryOnlyInProductAndDocs(t *testing.T) {
	// In-product disclosure: the Secrets page must label the not-yet-served slices.
	secretsPage := strings.ToLower(strings.Join([]string{
		read(t, "../web/src/pages/Secrets.tsx"),
		read(t, "../web/src/pages/secrets/SecretScanningWorkflow.tsx"),
		read(t, "../web/src/pages/secrets/EphemeralAPIKeyWorkflow.tsx"),
	}, "\n"))
	for _, m := range []string{
		"secret-scanning triage is library-only",
	} {
		if !strings.Contains(secretsPage, m) {
			t.Errorf("the assembled Secrets workflow must keep the honest library-only label for the secrets-expansion surfaces (missing %q) — TRACE-005", m)
		}
	}
	if !containsAll(secretsPage, []string{"ephemeral api-key issuance is served", "post /api/v1/ephemeral/api-keys", "trstctl-cli ephemeral api-keys issue", "api_token.revoked"}) {
		t.Error("the assembled Secrets workflow must disclose ephemeral API-key issuance as served now that F38 has API/CLI routes — TRACE-005")
	}
	if !containsAll(secretsPage, []string{"dynamic secret leases are served", "post /api/v1/secrets/leases", "secrets:read"}) {
		t.Error("web/src/pages/Secrets.tsx must disclose dynamic-secret leases as served now that F65 has API/CLI routes — TRACE-005")
	}
	// It must use the UnavailableState primitive (the honest "not served yet" UI), not
	// silently present these as working.
	if !strings.Contains(read(t, "../web/src/pages/Secrets.tsx"), "UnavailableState") {
		t.Error("web/src/pages/Secrets.tsx no longer uses UnavailableState for the unserved secrets surfaces; the TRACE-005 in-product disclosure has no anchor — revisit this reality test")
	}

	// Docs disclosure for secret-sync: library-only while no served importer exists.
	low := limLower(t)
	secretSyncServed := importsAnyOnServedPath(t, `trstctl.com/trstctl/internal/secretsync"`)
	if _, err := os.Stat("../internal/secretsync"); err != nil {
		t.Fatalf("internal/secretsync no longer exists; revisit this TRACE-005 reality test: %v", err)
	}
	if secretSyncServed {
		if strings.Contains(low, "secret-sync to external stores") && strings.Contains(low, "still library-only") {
			t.Error("internal/secretsync is now imported on the served path, but limitations.md still discloses secret-sync as \"still library-only\" — update the disclosure (TRACE-005)")
		}
	} else {
		if !containsAll(low, []string{"secret-sync to external stores", "still library-only"}) {
			t.Error("limitations.md must disclose secret-sync to external stores as still library-only while no served path imports internal/secretsync — TRACE-005")
		}
		if strings.Contains(low, "secret-sync is served") {
			t.Error("limitations.md over-claims secret-sync as served while no served path imports internal/secretsync — TRACE-005")
		}
	}
}

// ---- TRACE-006: incident execution + fleet-wide re-issuance + break-glass issue
//      and reconciliation served ------------------------------------------------

// TestIncidentAndFleetReissuanceServingStatusIsHonest pins TRACE-006. A
// single-identity credential-compromise incident IS served end-to-end, and
// compromised-issuer fleet re-issuance IS served through its own run API. Online
// m-of-n break-glass issue and offline-bundle reconciliation are also served, and
// both must record breakglass.issued audit evidence.
func TestIncidentAndFleetReissuanceServingStatusIsHonest(t *testing.T) {
	low := limLower(t)

	// Reality anchor (served side): the incident and fleet routes are registered and
	// their handlers exist.
	if !strings.Contains(read(t, "../internal/api/api.go"), `path: "/api/v1/incidents/executions"`) {
		t.Fatal("internal/api/api.go no longer registers /api/v1/incidents/executions; the TRACE-006 served-incident disclosure has no code anchor — revisit this reality test")
	}
	if !strings.Contains(read(t, "../internal/api/incidents.go"), "executeIncident") {
		t.Fatal("internal/api/incidents.go no longer serves executeIncident; the TRACE-006 served-incident disclosure has no code anchor — revisit this reality test")
	}
	if !strings.Contains(read(t, "../internal/api/api.go"), `path: "/api/v1/incidents/fleet-reissuance-runs"`) {
		t.Fatal("internal/api/api.go no longer registers /api/v1/incidents/fleet-reissuance-runs; the TRACE-006 served-fleet disclosure has no code anchor — revisit this reality test")
	}
	if !strings.Contains(read(t, "../internal/api/incident_fleet_reissuance.go"), "startFleetReissuance") {
		t.Fatal("internal/api/incident_fleet_reissuance.go no longer serves startFleetReissuance; revisit this TRACE-006 reality test")
	}
	if !strings.Contains(read(t, "../internal/api/api.go"), `path: "/api/v1/breakglass/reconcile"`) {
		t.Fatal("internal/api/api.go no longer registers /api/v1/breakglass/reconcile; the TRACE-006 break-glass reconciliation disclosure has no code anchor — revisit this reality test")
	}
	if !strings.Contains(read(t, "../internal/api/api.go"), `path: "/api/v1/breakglass/issue"`) {
		t.Fatal("internal/api/api.go no longer registers /api/v1/breakglass/issue; the TRACE-006 online break-glass disclosure has no code anchor — revisit this reality test")
	}
	for _, path := range []string{
		`path: "/api/v1/breakglass/issue-ceremonies"`,
		`path: "/api/v1/breakglass/rotate"`,
		`path: "/api/v1/breakglass/cross-sign"`,
	} {
		if !strings.Contains(read(t, "../internal/api/api.go"), path) {
			t.Fatalf("internal/api/api.go no longer registers %s; revisit the TRACE-006 lifecycle disclosure", path)
		}
	}
	if !strings.Contains(read(t, "../internal/server/breakglass.go"), "ReconcileBreakglass") {
		t.Fatal("internal/server/breakglass.go no longer wires break-glass reconciliation; revisit this TRACE-006 reality test")
	}
	if !strings.Contains(read(t, "../internal/server/run.go"), "breakglassRotationFromConfig") {
		t.Fatal("internal/server/run.go no longer production-assembles online break-glass; revisit this TRACE-006 reality test")
	}
	rotationSource := read(t, "../internal/server/breakglass_rotation.go")
	if !strings.Contains(rotationSource, "ValidateKeyCeremonyWithApprovalEvidenceTx") ||
		!strings.Contains(rotationSource, "EventCACeremonyApproved") {
		t.Fatal("online break-glass no longer binds signer actions to immutable authenticated ceremony evidence — TRACE-006")
	}

	// The served single-identity incident half must always be stated.
	if !strings.Contains(low, "incident execution") || !strings.Contains(low, "/api/v1/incidents/executions") {
		t.Error("limitations.md must disclose that single-identity incident execution is served at /api/v1/incidents/executions — TRACE-006")
	}
	if !strings.Contains(low, "/api/v1/incidents/fleet-reissuance-runs") {
		t.Error("limitations.md must disclose the served fleet re-issuance route — TRACE-006")
	}
	if !strings.Contains(low, "/api/v1/breakglass/issue") || !strings.Contains(low, "production-assembled") ||
		!strings.Contains(low, "authenticated immutable") || !strings.Contains(low, "request carries no approver names") {
		t.Error("limitations.md must disclose the configured production assembly and immutable-event approval boundary — TRACE-006")
	}
	if !strings.Contains(low, "/api/v1/breakglass/reconcile") || !strings.Contains(low, "breakglass.issued") {
		t.Error("limitations.md must disclose the served break-glass reconciliation route and audit event — TRACE-006")
	}
	if strings.Contains(low, "online m-of-n break-glass issuance is not production-assembled") || strings.Contains(low, "caller-supplied approver names") {
		t.Error("limitations.md still carries the superseded unassembled/caller-authored break-glass claim — TRACE-006")
	}
}

// ---- TRACE-007: AI-agent identity surface — F78 MCP investigation defaults read-only;
//      F61 broker issuance served when configured --------------------------------

// mcpInvestigationServed reports whether the read-only MCP investigation surface
// (F78) is wired into the served binary.
func mcpInvestigationServed(t *testing.T) bool {
	t.Helper()
	return importsAnyOnServedPath(t, `trstctl.com/trstctl/internal/mcpserver"`)
}

// brokerServed reports whether the F61 agent-identity broker issuance path is wired
// into a served endpoint.
func brokerServed(t *testing.T) bool {
	t.Helper()
	return importsAnyOnServedPath(t, `trstctl.com/trstctl/internal/broker"`)
}

// TestAIAgentBrokerNarrowedToServedReadOnlyMCPVsLibraryBroker pins TRACE-007. The
// served AI-agent-facing surface is the F78 MCP server. Its investigation tools are
// read-only by default, while certificate write tools are a separate, explicit,
// idempotent opt-in. F61 broker issuance is served only when its attestors, policy
// module, trust domain, and signer-backed issuing CA are configured. This guard binds
// both halves so the broker cannot be silently under-claimed as library-only and the
// default-read-only MCP claim stays grounded.
func TestAIAgentBrokerNarrowedToServedReadOnlyMCPVsLibraryBroker(t *testing.T) {
	// Reality anchor: the MCP server has no write tools unless WithWriteTools is
	// explicitly supplied. That keeps the investigation surface read-only by default.
	mcp := read(t, "../internal/mcpserver/mcpserver.go")
	for _, want := range []string{"func WithWriteTools()", "func (s *Server) HasWriteTool() bool { return len(s.writes) > 0 }", "issue_certificate", "rotate_certificate"} {
		if !strings.Contains(mcp, want) {
			t.Fatalf("internal/mcpserver no longer anchors guarded MCP write-tool behavior with %q — revisit TRACE-007", want)
		}
	}
	if !mcpInvestigationServed(t) {
		t.Fatal("the read-only MCP investigation surface is no longer wired into the served binary; revisit the TRACE-007 disclosure")
	}

	// Reality anchor: the F61 broker package + its lifecycle methods still exist,
	// and the served composition imports the package only for configured issuance.
	broker := read(t, "../internal/broker/broker.go")
	for _, sym := range []string{"func (b *Broker) Issue(", "func (b *Broker) Revoke(", "func (b *Broker) BlastRadius("} {
		if !strings.Contains(broker, sym) {
			t.Fatalf("internal/broker no longer exposes %q; the TRACE-007 broker disclosure has no code anchor — revisit this reality test", sym)
		}
	}

	// The F61 broker feature page must match code reality: served when configured
	// once internal/server imports internal/broker, library-only otherwise.
	wi := strings.Join(strings.Fields(strings.ToLower(read(t, "features/workload-identity.md"))), " ")
	if brokerServed(t) {
		if strings.Contains(wi, "not yet wired into a served endpoint") {
			t.Error("internal/broker is now wired into a served endpoint, but features/workload-identity.md still says the broker is \"not yet wired into a served endpoint\" — update the disclosure (TRACE-007)")
		}
		for _, want := range []string{
			"ai-agent identity broker",
			"post /api/v1/broker/agent-identities",
			"served when the agent broker is configured",
			"agent.identity.refused",
			"certificate.recorded",
		} {
			if !strings.Contains(wi, want) {
				t.Errorf("features/workload-identity.md must disclose served F61 broker issuance detail %q — TRACE-007", want)
			}
		}
	} else {
		if !containsAll(wi, []string{"ai-agent identity broker", "not yet wired into a served endpoint"}) {
			t.Error("features/workload-identity.md must disclose the F61 AI-agent identity broker as library-only (not yet wired into a served endpoint) — TRACE-007")
		}
		for _, oc := range []string{
			"the broker is served",
			"the ai-agent identity broker is served",
			"broker lifecycle is served",
		} {
			if strings.Contains(wi, oc) {
				t.Errorf("features/workload-identity.md over-claims the F61 broker as served (%q) while internal/broker has no served importer — TRACE-007", oc)
			}
		}
	}

	// The MCP feature page must keep the default-read-only framing and the explicit
	// guarded write-tool opt-in.
	gqa := strings.ToLower(read(t, "features/graph-query-ai.md"))
	for _, want := range []string{"read-only", "trstctl_ai_mcp_write_tools=true", "idempotency-key", "mcp.tool.write"} {
		if !strings.Contains(gqa, want) {
			t.Errorf("features/graph-query-ai.md must disclose guarded MCP write-tool posture (missing %q) — TRACE-007", want)
		}
	}
}

// ---- TRACE-008: licensed PQC end-to-end residuals are served but bounded -----------

// pqcMigrationServedInMPLCore reports whether the MPL core still exposes the
// proprietary PQC migration endpoint/CLI. PACKAGING-007 requires this to stay false.
func pqcMigrationServedInMPLCore(t *testing.T) bool {
	t.Helper()
	apiRoutes := read(t, "../internal/api/api.go")
	cliCommands := read(t, "../internal/cli/command.go")
	return strings.Contains(apiRoutes, "startPQCMigration") &&
		strings.Contains(apiRoutes, "rollbackPQCMigration") &&
		strings.Contains(cliCommands, `{"pqc", "migrations", "start"}`) &&
		strings.Contains(cliCommands, `{"pqc", "migrations", "rollback"}`)
}

// TestPQCMigrationServedResidualsDisclosed pins TRACE-008. PACKAGING-007 keeps
// PQC algorithms and the migration API behind the proprietary ee/ boundary. The
// shipped-binary census now proves the three old end-to-end gaps, while the docs
// must keep the exact client/connector boundary visible.
func TestPQCMigrationServedResidualsDisclosed(t *testing.T) {
	low := limLower(t)

	// Reality anchor (licensed side): the migration orchestrator still exists.
	if _, err := os.Stat("../ee/pqcmigration"); err != nil {
		t.Fatalf("ee/pqcmigration no longer exists; revisit this TRACE-008 reality test: %v", err)
	}

	if !containsAll(low, []string{
		"stock openssl 3.5 client",
		"pure ml-dsa-65 subject leaf",
		"two-entry response",
		"tls finding rollout",
		"envoy",
		"hybrid-to-pure cutover",
	}) {
		t.Error("limitations.md must disclose the served PQC proofs and their exact compatibility boundary — TRACE-008")
	}

	lcp := strings.ToLower(read(t, "features/lifecycle-and-pqc.md"))
	if pqcMigrationServedInMPLCore(t) {
		t.Error("PQC migration surfaced in MPL core API/CLI; PACKAGING-007 requires it to attach only through ee/ — TRACE-008")
	}
	for _, want := range []string{
		"proprietary ee",
		"not part of the mpl core openapi",
		"no mpl-core cli command",
		"served when the enterprise/pqc license attaches",
		"stock openssl 3.5",
		"two-entry classical + ml-dsa-65 response",
		"receiver readback and exact rollback",
	} {
		if !strings.Contains(lcp, want) {
			t.Errorf("features/lifecycle-and-pqc.md must disclose licensed PQC placement (missing %q) — TRACE-008", want)
		}
	}
	if strings.Contains(lcp, "every legacy client") && !strings.Contains(lcp, "not a claim about every legacy client") {
		t.Error("features/lifecycle-and-pqc.md over-claims universal PQC client compatibility — TRACE-008")
	}
}

// ---- TRACE-010: usability outcome NFRs have receipt-backed evidence -------------

// TestUsabilityOutcomeNFRsDisclosedAsUnmeasured keeps the original TRACE-010
// acceptance command name, but the expected reality changed: first-run timing now
// has an executable receipt, while NPS/operator satisfaction is guarded as
// "no numeric claim" until a real external study receipt exists.
func TestUsabilityOutcomeNFRsDisclosedAsUnmeasured(t *testing.T) {
	low := limLower(t)

	for _, m := range []string{
		"usability outcome nfrs are evidence-gated",
		"usability-slo-001",
		"scripts/usability/first-run-receipt.json",
		"automated wizard timing",
		"operator-study-receipt.json",
		"no numeric nps",
		"nps",
	} {
		if !strings.Contains(low, m) {
			t.Errorf("limitations.md must disclose receipt-backed usability outcome NFRs (missing marker %q) — TRACE-010", m)
		}
	}
	for _, oc := range []string{
		"usability outcome nfrs are aspirational and unmeasured",
		"no automated ci measurement of first-run",
		"nps is measured",
		"operator satisfaction is measured",
	} {
		if strings.Contains(low, oc) {
			t.Errorf("limitations.md carries stale or over-claiming usability NFR copy (%q) — TRACE-010", oc)
		}
	}

	var firstRun struct {
		SchemaVersion int      `json:"schema_version"`
		ID            string   `json:"id"`
		GeneratedAt   string   `json:"generated_at"`
		Command       []string `json:"command"`
		TestAnchor    string   `json:"test_anchor"`
		SLO           struct {
			TargetMS float64 `json:"target_ms"`
		} `json:"slo"`
		Measurements []struct {
			DurationMS float64 `json:"duration_ms"`
			Met        bool    `json:"met"`
		} `json:"measurements"`
		Summary struct {
			OK         bool    `json:"ok"`
			Met        bool    `json:"met"`
			DurationMS float64 `json:"duration_ms"`
			TargetMS   float64 `json:"target_ms"`
		} `json:"summary"`
	}
	if err := json.Unmarshal([]byte(read(t, "../scripts/usability/first-run-receipt.json")), &firstRun); err != nil {
		t.Fatalf("scripts/usability/first-run-receipt.json must be a valid receipt: %v", err)
	}
	if firstRun.SchemaVersion != 1 || firstRun.ID != "USABILITY-SLO-001" {
		t.Fatalf("first-run receipt identity = version %d / id %q, want USABILITY-SLO-001 schema v1", firstRun.SchemaVersion, firstRun.ID)
	}
	if _, err := time.Parse(time.RFC3339, firstRun.GeneratedAt); err != nil {
		t.Fatalf("first-run receipt generated_at must be RFC3339: %v", err)
	}
	if !firstRun.Summary.OK || !firstRun.Summary.Met || firstRun.Summary.DurationMS <= 0 || firstRun.Summary.DurationMS > firstRun.Summary.TargetMS {
		t.Fatalf("first-run receipt is not green or exceeds target: %+v", firstRun.Summary)
	}
	if firstRun.SLO.TargetMS != firstRun.Summary.TargetMS || firstRun.SLO.TargetMS <= 0 {
		t.Fatalf("first-run receipt target mismatch: slo=%v summary=%v", firstRun.SLO.TargetMS, firstRun.Summary.TargetMS)
	}
	if len(firstRun.Measurements) == 0 {
		t.Fatal("first-run receipt must include at least one measurement")
	}
	if !containsAll(strings.ToLower(strings.Join(firstRun.Command, " ")), []string{"npm", "first-run.test.tsx"}) {
		t.Fatalf("first-run receipt command must run the served-capability journey test, got %q", strings.Join(firstRun.Command, " "))
	}
	if firstRun.TestAnchor != "web/src/__tests__/first-run.test.tsx" {
		t.Fatalf("first-run receipt test anchor = %q, want web/src/__tests__/first-run.test.tsx", firstRun.TestAnchor)
	}

	var operatorStudy struct {
		SchemaVersion int    `json:"schema_version"`
		ID            string `json:"id"`
		Status        string `json:"status"`
		Participants  int    `json:"participants"`
		ReleaseGate   string `json:"release_gate"`
	}
	if err := json.Unmarshal([]byte(read(t, "../scripts/usability/operator-study-receipt.json")), &operatorStudy); err != nil {
		t.Fatalf("scripts/usability/operator-study-receipt.json must be a valid receipt: %v", err)
	}
	if operatorStudy.SchemaVersion != 1 || operatorStudy.ID != "USABILITY-SLO-002" {
		t.Fatalf("operator-study receipt identity = version %d / id %q, want USABILITY-SLO-002 schema v1", operatorStudy.SchemaVersion, operatorStudy.ID)
	}
	if operatorStudy.Status != "no_numeric_claim" || operatorStudy.Participants != 0 {
		t.Fatalf("operator-study receipt should be a no-numeric-claim guard until a real study exists: %+v", operatorStudy)
	}
	if !containsAll(strings.ToLower(operatorStudy.ReleaseGate), []string{"release", "nps", "claim"}) {
		t.Fatalf("operator-study receipt release gate must explicitly block NPS claims, got %q", operatorStudy.ReleaseGate)
	}

	for _, path := range []string{"../scripts/usability/measure-first-run.mjs", "../scripts/usability/verify-release-evidence.py", "usability.md"} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("TRACE-010 usability evidence artifact %s missing: %v", path, err)
		}
	}
	ci := read(t, "../.github/workflows/ci.yml")
	for _, want := range []string{"First-run usability receipt", "scripts/usability/measure-first-run.mjs", "scripts/usability/verify-release-evidence.py", "first-run-usability-receipt"} {
		if !strings.Contains(ci, want) {
			t.Errorf("ci.yml missing usability evidence gate marker %q — TRACE-010", want)
		}
	}
	releaseScript := read(t, "../scripts/release/slsa-release-provenance.sh")
	for _, want := range []string{"scripts/usability/verify-release-evidence.py", "TRSTCTL_RELEASE_NOTES_FILE", "--release-notes-text"} {
		if !strings.Contains(releaseScript, want) {
			t.Errorf("release provenance script must gate release notes on usability evidence (missing %q) — TRACE-010", want)
		}
	}
	releaseWorkflow := read(t, "../.github/workflows/release.yml")
	for _, want := range []string{"Verify usability release evidence", "scripts/usability/verify-release-evidence.py"} {
		if !strings.Contains(releaseWorkflow, want) {
			t.Errorf("release.yml must gate direct release-note creation on usability evidence (missing %q) — TRACE-010", want)
		}
	}

	// Reality anchor: performance/scale NFR evidence still exists alongside the new
	// usability evidence. If these disappear, the NFR page needs a broader rewrite.
	if _, err := os.Stat("../scripts/perf/artifacts/live-load-baseline.json"); err != nil {
		t.Fatalf("scripts/perf/artifacts/live-load-baseline.json no longer exists; the TRACE-010 NFR evidence contrast has no served live-load anchor — revisit this reality test: %v", err)
	}
	if _, err := os.Stat("../internal/perf/soak.go"); err != nil {
		t.Fatalf("internal/perf/soak.go no longer exists; the TRACE-010 NFR evidence contrast has no anchor — revisit this reality test: %v", err)
	}
	if _, err := os.Stat("../scripts/perf/soak.sh"); err != nil {
		t.Fatalf("scripts/perf/soak.sh no longer exists; the TRACE-010 NFR evidence contrast has no anchor — revisit this reality test: %v", err)
	}
}
