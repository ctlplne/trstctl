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
	"os"
	"strings"
	"testing"
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

// ---- TRACE-002: discovery control plane + network/cloud/CT/drift execution served;
//      SSH host-key execution still library/agent-owned --------------------------

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
	return importsAnyOnServedPath(t,
		`trstctl.com/trstctl/internal/discovery/sshscan"`,
	)
}

// TestDiscoveryServedControlPlaneAndNetworkScanVsLibraryCollectorsIsHonest pins
// TRACE-002. The running binary serves the discovery control/scheduling API AND
// executes real network, cloud-certificate, CT-log, and drift scans end-to-end via the
// outbox worker; SSH host-key execution is still library/agent work. The disclosure must
// state both halves honestly and not over-claim the unserved collector.
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

	// Unserved-collector half: SSH host-key execution is still library/agent work.
	if sshCollectorServed(t) {
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

// ---- TRACE-003: managed-key (BYOK/HSM) lifecycle served; in-process BYOK + m-of-n
//      still library-only --------------------------------------------------------

// managedKeysServed reports whether the BYOK/HSM managed-key lifecycle is served
// (CRYPTO-005). The served service lives in internal/managedkeys and is wired via
// internal/api + internal/server.
func managedKeysServed(t *testing.T) bool {
	t.Helper()
	return importsAnyOnServedPath(t, `trstctl.com/trstctl/internal/managedkeys"`)
}

// TestManagedKeyLifecycleServedAndRemainingCustodyGapIsHonest pins TRACE-003. The
// HSM/KMS-resident managed-key lifecycle (generate/rotate/revoke/zeroize, dual
// control) is SERVED. What remains library-tier is the in-process local CA/KEK BYOK
// verbs and a served m-of-n break-glass flow. The disclosure must reflect the served
// surface AND keep the residual gap honest.
func TestManagedKeyLifecycleServedAndRemainingCustodyGapIsHonest(t *testing.T) {
	low := limLower(t)

	// Reality anchor (served side): the managed-key routes are registered by the
	// served API and the service exists.
	apiRoutes := read(t, "../internal/api/api.go")
	for _, route := range []string{`path: "/api/v1/managed-keys"`, `path: "/api/v1/managed-keys/rotate"`} {
		if !strings.Contains(apiRoutes, route) {
			t.Fatalf("internal/api/api.go no longer registers %s; the TRACE-003 served-managed-key disclosure has no code anchor — revisit this reality test", route)
		}
	}
	if _, err := os.Stat("../internal/managedkeys"); err != nil {
		t.Fatalf("internal/managedkeys no longer exists; revisit this TRACE-003 reality test: %v", err)
	}
	// Reality anchor (library side): the in-process BYOK lifecycle the residual gap
	// rests on still exists.
	if _, err := os.Stat("../internal/crypto/byok"); err != nil {
		t.Fatalf("internal/crypto/byok no longer exists; the TRACE-003 in-process-BYOK residual disclosure has no code anchor — revisit this reality test: %v", err)
	}

	if managedKeysServed(t) {
		// Served: the disclosure must name the served managed-key surface and must
		// NOT claim the HSM/KMS-resident lifecycle is still unserved.
		if !strings.Contains(low, "/api/v1/managed-keys") {
			t.Error("the managed-key lifecycle is served (CRYPTO-005) but limitations.md does not name the served /api/v1/managed-keys surface — TRACE-003")
		}
		for _, stale := range []string{
			"the hsm/kms-resident lifecycle is not served",
			"managed keys are library-only",
		} {
			if strings.Contains(low, stale) {
				t.Errorf("limitations.md still discloses the managed-key lifecycle as unserved (%q) after CRYPTO-005 served it — update the disclosure (TRACE-003)", stale)
			}
		}
		// And the residual gap must stay honestly disclosed: the in-process BYOK
		// verbs and m-of-n break-glass are still library-tier.
		for _, m := range []string{"in-process", "m-of-n break-glass"} {
			if !strings.Contains(low, m) {
				t.Errorf("limitations.md must keep disclosing the still-library-tier custody residual (missing marker %q) — TRACE-003", m)
			}
		}
		return
	}
	// Not served (regression): the disclosure must not claim it is served.
	if strings.Contains(low, "/api/v1/managed-keys") && !strings.Contains(low, "future work") {
		t.Error("limitations.md names /api/v1/managed-keys as served but no served path imports internal/managedkeys — TRACE-003 regression")
	}
}

// ---- TRACE-004: deployment connectors — native/plugin target mutation served ----

// TestConnectorDeliveryServedVsLibraryMutationIsHonest pins TRACE-004. The connector
// catalog and delivery receipts are served, and direct credential-carrying
// connector.deploy payloads mutate targets through either the native registry or a
// provenance-verified signed connector plugin. Metadata-only lifecycle receipts remain
// explicitly unrouted so the docs cannot claim bytes were deployed when no key material
// is available.
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
	// Reality anchor (served mutation side): the native registry is on Deps and the
	// dispatcher records a native delivered receipt when it owns a credential-carrying
	// connector.deploy payload.
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
	if !anyTestDeclaresUnder(t, "../internal/server", "TestServedNativeConnectorRegistryDeploysToACMAndAzureKVEmulators") {
		t.Fatal("TRACE-004 requires the served ACM + Azure KV native connector acceptance test")
	}
	// Reality anchor (connector side): the connector implementation bodies still exist.
	if _, err := os.Stat("../internal/connector"); err != nil {
		t.Fatalf("internal/connector no longer exists; revisit this TRACE-004 reality test: %v", err)
	}

	// The served catalog/receipts half must always be stated.
	if !strings.Contains(low, "connector.delivery.recorded") {
		t.Error("limitations.md must disclose that the binary serves the connector catalog and delivery receipts — TRACE-004")
	}
	// The served mutation boundary must state both real routes and the honest unrouted
	// case for lifecycle-only metadata.
	if !containsAll(low, []string{"deployment connector target mutation", "native `connectorregistry`", "signed wasm connector plugin", "cert_pem", "key_pem", "unrouted"}) {
		t.Error("limitations.md must disclose native/plugin connector mutation plus the credential-payload and unrouted boundaries — TRACE-004")
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
	secretsPage := strings.ToLower(read(t, "../web/src/pages/Secrets.tsx"))
	for _, m := range []string{
		"secret-scanning triage is library-only",
	} {
		if !strings.Contains(secretsPage, m) {
			t.Errorf("web/src/pages/Secrets.tsx must keep the honest library-only label for the secrets-expansion surfaces (missing %q) — TRACE-005", m)
		}
	}
	if !containsAll(secretsPage, []string{"ephemeral api-key issuance is served", "post /api/v1/ephemeral/api-keys", "trstctl-cli ephemeral api-keys issue", "api_token.revoked"}) {
		t.Error("web/src/pages/Secrets.tsx must disclose ephemeral API-key issuance as served now that F38 has API/CLI routes — TRACE-005")
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

// ---- TRACE-006: incident execution served; fleet-wide re-issuance + break-glass
//      library/API-only ----------------------------------------------------------

// TestIncidentExecutionServedVsFleetReissuanceLibraryIsHonest pins TRACE-006. A
// single-identity credential-compromise incident IS served end-to-end
// (POST /api/v1/incidents/executions, with a sealed evidence pack). What is NOT a
// served end-to-end workflow is fleet-wide re-issuance and m-of-n break-glass.
func TestIncidentExecutionServedVsFleetReissuanceLibraryIsHonest(t *testing.T) {
	low := limLower(t)

	// Reality anchor (served side): the incident-execution route is registered and
	// the handler exists.
	if !strings.Contains(read(t, "../internal/api/api.go"), `path: "/api/v1/incidents/executions"`) {
		t.Fatal("internal/api/api.go no longer registers /api/v1/incidents/executions; the TRACE-006 served-incident disclosure has no code anchor — revisit this reality test")
	}
	if !strings.Contains(read(t, "../internal/api/incidents.go"), "executeIncident") {
		t.Fatal("internal/api/incidents.go no longer serves executeIncident; the TRACE-006 served-incident disclosure has no code anchor — revisit this reality test")
	}

	// The served single-identity incident half must always be stated.
	if !strings.Contains(low, "incident execution") || !strings.Contains(low, "/api/v1/incidents/executions") {
		t.Error("limitations.md must disclose that single-identity incident execution is served at /api/v1/incidents/executions — TRACE-006")
	}
	// The fleet-wide re-issuance + break-glass gap must always be disclosed in the
	// INCIDENT context (not merely mentioned elsewhere): the served-list bullet states
	// it is "not this surface", and the React-console section labels the
	// reissuance/break-glass workflows API-only. Bind to those exact phrases so the
	// disclosure cannot be removed while an unrelated break-glass mention elsewhere
	// keeps a looser check green.
	// (Start the marker after "fleet-wide", which the source emphasizes with Markdown
	// asterisks that survive the lowercase collapse.)
	if !strings.Contains(low, "re-issuance and m-of-n break-glass are not this surface") {
		t.Error("limitations.md must disclose, in the incident-execution context, that fleet-wide re-issuance and m-of-n break-glass are NOT the served incident surface — TRACE-006")
	}
	if !strings.Contains(low, "reissuance/break-glass workflows") {
		t.Error("limitations.md must keep the React-console label that fleet reissuance/break-glass workflows are API-only/library-only — TRACE-006")
	}
	for _, oc := range []string{
		"fleet-wide re-issuance is served",
		"fleet reissuance is served",
		"break-glass is served",
	} {
		if strings.Contains(low, oc) {
			t.Errorf("limitations.md over-claims fleet re-issuance / break-glass as served (%q) — TRACE-006", oc)
		}
	}
}

// ---- TRACE-007: AI-agent identity surface — F78 MCP investigation read-only;
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
// served AI-agent-facing surface is the F78 MCP server, which is strictly READ-ONLY
// (no write/remediation tools). F61 broker issuance is served only when its attestors,
// policy module, trust domain, and signer-backed issuing CA are configured. This guard
// binds both halves so the broker cannot be silently under-claimed as library-only and
// the read-only MCP claim stays grounded.
func TestAIAgentBrokerNarrowedToServedReadOnlyMCPVsLibraryBroker(t *testing.T) {
	// Reality anchor: the MCP server is read-only by construction (HasWriteTool is
	// hard-coded false). This is what makes the "read-only investigation" claim true.
	mcp := read(t, "../internal/mcpserver/mcpserver.go")
	if !strings.Contains(mcp, "func (s *Server) HasWriteTool() bool { return false }") {
		t.Fatal("internal/mcpserver no longer hard-codes HasWriteTool() == false; the TRACE-007 read-only-MCP disclosure has no code anchor — revisit this reality test")
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

	// The MCP feature page must keep the read-only framing (no write/remediation
	// tools), the anchor for narrowing the AI-agent claim.
	gqa := strings.ToLower(read(t, "features/graph-query-ai.md"))
	if !strings.Contains(gqa, "read-only") || !strings.Contains(gqa, "no remediation tools") {
		t.Error("features/graph-query-ai.md must keep disclosing the MCP server as read-only with no remediation tools — TRACE-007")
	}
}

// ---- TRACE-008: PQC primitives in place; pure-subject and broad rollout gaps remain -

// pqcMigrationServed reports whether the PQC migration orchestrator is wired into a
// served endpoint/CLI.
func pqcMigrationServed(t *testing.T) bool {
	t.Helper()
	apiRoutes := read(t, "../internal/api/api.go")
	cliCommands := read(t, "../internal/cli/command.go")
	return strings.Contains(apiRoutes, "startPQCMigration") &&
		strings.Contains(apiRoutes, "rollbackPQCMigration") &&
		strings.Contains(cliCommands, `{"pqc", "migrations", "start"}`) &&
		strings.Contains(cliCommands, `{"pqc", "migrations", "rollback"}`)
}

// TestPQCMigrationNotTraceCompleteDisclosed pins TRACE-008. The PQC crypto primitives
// (ML-DSA/ML-KEM/SLH-DSA/hybrid) are in place behind the AN-3 boundary, but
// pure ML-DSA subject certificates and broad rollout automation are NOT end-to-end.
// The disclosure must keep that gap honest while acknowledging the served migration
// trigger for CBOM certificate-key assets.
func TestPQCMigrationNotTraceCompleteDisclosed(t *testing.T) {
	low := limLower(t)

	// Reality anchor (library side): the migration orchestrator still exists.
	if _, err := os.Stat("../internal/pqcmigration"); err != nil {
		t.Fatalf("internal/pqcmigration no longer exists; revisit this TRACE-008 reality test: %v", err)
	}

	// The "not yet end-to-end" gaps (pure subject certs + broad rollout automation)
	// must always be disclosed in limitations.md.
	if !containsAll(low, []string{"not yet", "pure ml-dsa subject certificates", "automated rollout"}) {
		t.Error("limitations.md must disclose that pure-subject PQC certificates and broad rollout automation are not yet end-to-end — TRACE-008")
	}

	// The lifecycle-and-pqc feature page must not keep the old no-trigger disclosure
	// once the served endpoint and CLI exist.
	lcp := strings.ToLower(read(t, "features/lifecycle-and-pqc.md"))
	if pqcMigrationServed(t) {
		if strings.Contains(lcp, "no cli/api trigger yet") {
			t.Error("internal/pqcmigration is now wired into a served trigger, but features/lifecycle-and-pqc.md still says \"no CLI/API trigger yet\" — update the disclosure (TRACE-008)")
		}
		if !strings.Contains(lcp, "served for cbom certificate-key assets") {
			t.Error("features/lifecycle-and-pqc.md must describe the served PQC migration trigger scope — TRACE-008")
		}
	} else {
		if !strings.Contains(lcp, "no cli/api trigger yet") {
			t.Error("features/lifecycle-and-pqc.md must disclose that PQC migration has no CLI/API trigger yet (the orchestrator is library-complete) — TRACE-008")
		}
		if strings.Contains(lcp, "pqc migration is served") || strings.Contains(lcp, "fleet-wide rollout is served") {
			t.Error("features/lifecycle-and-pqc.md over-claims PQC migration as served while internal/pqcmigration has no served importer — TRACE-008")
		}
	}
}

// ---- TRACE-011: usability outcome NFRs are aspirational/unmeasured ---------------

// TestUsabilityOutcomeNFRsDisclosedAsUnmeasured pins TRACE-011. Performance/scale
// NFRs have executable evidence (smoke + soak gates); usability outcome NFRs (timed
// first-run wall-clock, NPS/satisfaction) are aspirational and NOT measured in CI.
// The disclosure must say so, and the performance NFRs it contrasts against must
// remain backed by the real gates (so "measured" stays true).
func TestUsabilityOutcomeNFRsDisclosedAsUnmeasured(t *testing.T) {
	low := limLower(t)

	// The honest "aspirational/unmeasured" disclosure for usability outcome NFRs.
	for _, m := range []string{
		"usability outcome nfrs are aspirational and unmeasured",
		"no automated ci measurement",
		"timed first-run",
		"nps",
	} {
		if !strings.Contains(low, m) {
			t.Errorf("limitations.md must disclose usability outcome NFRs (timed first-run / NPS) as aspirational and unmeasured (missing marker %q) — TRACE-011", m)
		}
	}
	// It must not over-claim a measured first-run/NPS number.
	for _, oc := range []string{
		"first-run time is measured",
		"nps is measured",
		"operator satisfaction is measured",
	} {
		if strings.Contains(low, oc) {
			t.Errorf("limitations.md over-claims a usability outcome NFR as measured (%q) while none is benchmarked — TRACE-011", oc)
		}
	}

	// Reality anchor: the contrast it draws — that performance/scale NFRs ARE measured
	// — must stay true. The executable evidence exists (smoke + soak gates). If the
	// soak gate denominator is removed, this disclosure's "measured" contrast rots.
	if _, err := os.Stat("../internal/perf/soak.go"); err != nil {
		t.Fatalf("internal/perf/soak.go no longer exists; the TRACE-011 measured-vs-aspirational contrast has no anchor — revisit this reality test: %v", err)
	}
	if _, err := os.Stat("../scripts/perf/soak.sh"); err != nil {
		t.Fatalf("scripts/perf/soak.sh no longer exists; the TRACE-011 measured-vs-aspirational contrast has no anchor — revisit this reality test: %v", err)
	}
}
