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

// ---- TRACE-002: discovery control plane + network scan execution served;
//      the other collectors (ssh/cloud/CT) library-only ---------------------------

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

// nonNetworkCollectorsServed reports whether any of the OTHER discovery collectors
// (ssh/cloud-cert/CT) are wired into the served binary. Today none is.
func nonNetworkCollectorsServed(t *testing.T) bool {
	t.Helper()
	return importsAnyOnServedPath(t,
		`trstctl.com/trstctl/internal/discovery/sshscan"`,
		`trstctl.com/trstctl/internal/discovery/cloudcert"`,
		`trstctl.com/trstctl/internal/discovery/ctmonitor"`,
	)
}

// TestDiscoveryServedControlPlaneAndNetworkScanVsLibraryCollectorsIsHonest pins
// TRACE-002. The running binary serves the discovery control/scheduling API AND
// executes a real network certificate scan end-to-end (netscan via the outbox
// worker); the SSH/cloud-cert/CT collectors are library-only. The disclosure must
// state all three honestly and not over-claim the unserved collectors.
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
	// Reality anchor (library side): the unserved collector packages still exist, so a
	// "library-only" claim about them is grounded.
	for _, pkg := range []string{"sshscan", "cloudcert", "ctmonitor"} {
		if _, err := os.Stat("../internal/discovery/" + pkg); err != nil {
			t.Fatalf("internal/discovery/%s no longer exists; revisit this TRACE-002 reality test", pkg)
		}
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

	// Unserved-collectors half: ssh/cloud/CT collectors are library-only.
	// Rebound off the prior internal-flavored "no importer on the served path" marker to
	// the customer-facing phrasing the page now uses for the same fact: these collectors
	// have "no path into the served worker" (library-only). It is specific to the
	// SSH/cloud-cert/CT collectors' served status, so the bi-directional drift protection
	// is preserved without an internal token.
	if nonNetworkCollectorsServed(t) {
		// One of them is now wired in: the library-only claim would be a stale
		// under-claim. Require it to be retired.
		if containsAll(low, []string{"discovery scanners/collectors other than network scan", "no path into the served worker"}) {
			t.Error("an SSH/cloud-cert/CT discovery collector is now wired into the served worker, but limitations.md still says those collectors have \"no path into the served worker\" — update the disclosure (TRACE-002 served increment landed)")
		}
		return
	}
	for _, m := range []string{"discovery scanners/collectors other than network scan", "no path into the served worker"} {
		if !strings.Contains(low, m) {
			t.Errorf("limitations.md must disclose the SSH/cloud-cert/CT discovery collectors as library-only (missing marker %q) — TRACE-002", m)
		}
	}
	for _, oc := range []string{
		"all discovery scans are served",
		"the ct monitor is served",
		"cloud-certificate discovery is served",
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

// ---- TRACE-004: deployment connectors — catalog/receipts served; target mutation
//      library-only (signed plugin) ----------------------------------------------

// TestConnectorDeliveryServedVsLibraryMutationIsHonest pins TRACE-004. The connector
// catalog and delivery receipts are served; actual target mutation is routed only by
// a provenance-verified signed connector plugin (otherwise an `unrouted` receipt).
// The disclosure must say both: receipts served, mutation library/plugin-gated.
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
	// Reality anchor (library side): the connector implementation bodies still exist.
	if _, err := os.Stat("../internal/connector"); err != nil {
		t.Fatalf("internal/connector no longer exists; revisit this TRACE-004 reality test: %v", err)
	}

	// The served-receipts half must always be stated.
	if !strings.Contains(low, "serves the connector catalog and delivery receipts") {
		t.Error("limitations.md must disclose that the binary serves the connector catalog and delivery receipts — TRACE-004")
	}
	// The library/plugin-gated-mutation half must always be stated, and must not be
	// over-claimed as a generally-served target mutation.
	if !containsAll(low, []string{"actual target mutation is routed only when", "signed connector plugin", "unrouted"}) {
		t.Error("limitations.md must disclose that actual connector target mutation is routed only by a provenance-verified signed plugin (otherwise an unrouted receipt) — TRACE-004")
	}
	for _, oc := range []string{
		"connector target mutation is served",
		"the binary deploys to connector targets",
		"deployment connectors are served end-to-end",
	} {
		if strings.Contains(low, oc) {
			t.Errorf("limitations.md over-claims connector deployment as served (%q) while target mutation is plugin-gated/library-only — TRACE-004", oc)
		}
	}
}

// ---- TRACE-005: secrets expansion (ephemeral keys, scanning triage, dynamic
//      secrets, transit/KMIP, secret-sync) — disclosed library-only in-product ----

// TestSecretsExpansionDisclosedLibraryOnlyInProductAndDocs pins TRACE-005. The web
// console honestly labels the not-yet-served secrets surfaces as library-only/
// unavailable, and limitations.md discloses secret-sync and transit/KMIP as still
// library-only. This binds the in-product disclosure to the web source and the docs
// disclosure to the code reality.
func TestSecretsExpansionDisclosedLibraryOnlyInProductAndDocs(t *testing.T) {
	// In-product disclosure: the Secrets page must label the not-yet-served slices.
	secretsPage := strings.ToLower(read(t, "../web/src/pages/Secrets.tsx"))
	for _, m := range []string{
		"ephemeral api-key issuance is library-only",
		"secret-scanning triage is library-only",
		"library-only", // dynamic-secret lease verbs
	} {
		if !strings.Contains(secretsPage, m) {
			t.Errorf("web/src/pages/Secrets.tsx must keep the honest library-only label for the secrets-expansion surfaces (missing %q) — TRACE-005", m)
		}
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

// ---- TRACE-007: AI-agent identity surface — F78 MCP investigation served
//      read-only; F61 broker lifecycle library-only ------------------------------

// mcpInvestigationServed reports whether the read-only MCP investigation surface
// (F78) is wired into the served binary.
func mcpInvestigationServed(t *testing.T) bool {
	t.Helper()
	return importsAnyOnServedPath(t, `trstctl.com/trstctl/internal/mcpserver"`)
}

// brokerServed reports whether the full F61 agent-identity broker lifecycle is wired
// into a served endpoint. Today it is not (internal/broker is library-only).
func brokerServed(t *testing.T) bool {
	t.Helper()
	return importsAnyOnServedPath(t, `trstctl.com/trstctl/internal/broker"`)
}

// TestAIAgentBrokerNarrowedToServedReadOnlyMCPVsLibraryBroker pins TRACE-007. The
// served AI-agent-facing surface is the F78 MCP server, which is strictly READ-ONLY
// (no write/remediation tools). The full F61 broker lifecycle (issue/revoke/
// blast-radius for agent credentials) is library-only ("not yet wired into a served
// endpoint"). This guard binds both halves so the broker cannot be silently claimed
// as a served lifecycle and the read-only MCP claim stays grounded.
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

	// Reality anchor (library side): the F61 broker package + its lifecycle methods
	// still exist, so the "library-only broker" disclosure is grounded.
	broker := read(t, "../internal/broker/broker.go")
	for _, sym := range []string{"func (b *Broker) Issue(", "func (b *Broker) Revoke(", "func (b *Broker) BlastRadius("} {
		if !strings.Contains(broker, sym) {
			t.Fatalf("internal/broker no longer exposes %q; the TRACE-007 library-only-broker disclosure has no code anchor — revisit this reality test", sym)
		}
	}

	// The F61 broker feature page must disclose the broker as library-only and must
	// not over-claim a served broker lifecycle, until brokerServed flips true.
	wi := strings.Join(strings.Fields(strings.ToLower(read(t, "features/workload-identity.md"))), " ")
	if brokerServed(t) {
		if strings.Contains(wi, "not yet wired into a served endpoint") {
			t.Error("internal/broker is now wired into a served endpoint, but features/workload-identity.md still says the broker is \"not yet wired into a served endpoint\" — update the disclosure (TRACE-007)")
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

// ---- TRACE-008: PQC primitives in place; fleet-wide migration + protocol-wide
//      issuance not trace-complete -------------------------------------------------

// pqcMigrationServed reports whether the PQC migration orchestrator is wired into a
// served endpoint/CLI. Today it is not (internal/pqcmigration is library-only).
func pqcMigrationServed(t *testing.T) bool {
	t.Helper()
	return importsAnyOnServedPath(t, `trstctl.com/trstctl/internal/pqcmigration"`)
}

// TestPQCMigrationNotTraceCompleteDisclosed pins TRACE-008. The PQC crypto primitives
// (ML-DSA/ML-KEM/SLH-DSA/hybrid) are in place behind the AN-3 boundary, but
// fleet-wide migration orchestration and PQC issuance through every enrollment
// protocol are NOT end-to-end. The disclosure must keep that gap honest and not
// over-claim a served migration trigger.
func TestPQCMigrationNotTraceCompleteDisclosed(t *testing.T) {
	low := limLower(t)

	// Reality anchor (library side): the migration orchestrator still exists.
	if _, err := os.Stat("../internal/pqcmigration"); err != nil {
		t.Fatalf("internal/pqcmigration no longer exists; revisit this TRACE-008 reality test: %v", err)
	}

	// The "not yet end-to-end" gap (fleet-wide migration + protocol-wide issuance)
	// must always be disclosed in limitations.md.
	if !containsAll(low, []string{"not yet", "fleet-wide", "migration orchestration"}) {
		t.Error("limitations.md must disclose that fleet-wide PQC migration orchestration is not yet end-to-end — TRACE-008")
	}

	// The lifecycle-and-pqc feature page must disclose the no-trigger gap and bind it
	// to the library-complete orchestrator, until pqcMigrationServed flips true.
	lcp := strings.ToLower(read(t, "features/lifecycle-and-pqc.md"))
	if pqcMigrationServed(t) {
		if strings.Contains(lcp, "no cli/api trigger yet") {
			t.Error("internal/pqcmigration is now wired into a served trigger, but features/lifecycle-and-pqc.md still says \"no CLI/API trigger yet\" — update the disclosure (TRACE-008)")
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
