// SPDX-License-Identifier: MPL-2.0

package netexec

import (
	"reflect"
	"testing"
)

func TestReviewedExecAllowlistPinsPerfLiveSampler(t *testing.T) {
	want := map[string]bool{
		"liveSignerBinary": true,
		"commandOutput":    true,
	}
	if got := reviewedExecUses["internal/perf/live.go"]; !reflect.DeepEqual(got, want) {
		t.Fatalf("internal/perf/live.go reviewed exec allowlist = %#v, want %#v", got, want)
	}
}

func TestReviewedExecAllowlistPinsDODCensusProcessBoundaries(t *testing.T) {
	want := map[string]map[string]bool{
		"tools/dodcensus/main.go": {
			"Run": true,
		},
		"tools/dodcensus/proof/proof.go": {
			"StartCommand":   true,
			"StartContainer": true,
		},
		"tools/dodcensus/proof/launched.go": {
			"buildShippedProcess":        true,
			"companionProductionClosure": true,
			"CreateToken":                true,
			"Start":                      true,
		},
		"tools/dodcensus/runtime_runner.go": {
			"runHostCommand": true,
		},
		"tools/dodcensus/substrate_broker.go": {
			"launch": true,
		},
	}
	for file, functions := range want {
		if got := reviewedExecUses[file]; !reflect.DeepEqual(got, functions) {
			t.Fatalf("%s reviewed exec allowlist = %#v, want %#v", file, got, functions)
		}
	}
}

func TestReviewedExecAllowlistPinsPQCOperatorLabBoundary(t *testing.T) {
	want := map[string]bool{"newValidatedCommand": true}
	if got := reviewedExecUses["tools/pqclab/main.go"]; !reflect.DeepEqual(got, want) {
		t.Fatalf("tools/pqclab/main.go reviewed exec allowlist = %#v, want %#v", got, want)
	}
}

func TestReviewedExecAllowlistPinsConnectorLocalOpsBoundary(t *testing.T) {
	want := map[string]bool{"ExecContext": true}
	if got := reviewedExecUses["internal/connector/localops.go"]; !reflect.DeepEqual(got, want) {
		t.Fatalf("internal/connector/localops.go reviewed exec allowlist = %#v, want %#v", got, want)
	}
}

// TestAmbientHTTPGuardPackagesStayTwo pins the ONLY structural exemption from
// the SEC-005 ambient-client rule. internal/netsec and internal/egress are the
// packages that build the sanctioned clients, so the rule cannot apply to them
// without being circular; anything else added here would be a hole, not an
// exemption.
func TestAmbientHTTPGuardPackagesStayTwo(t *testing.T) {
	want := map[string]bool{
		"trstctl.com/trstctl/internal/netsec": true,
		"trstctl.com/trstctl/internal/egress": true,
	}
	if !reflect.DeepEqual(ambientHTTPClientGuardPackages, want) {
		t.Fatalf("ambientHTTPClientGuardPackages = %#v, want %#v", ambientHTTPClientGuardPackages, want)
	}
}

// TestAmbientHTTPBurnDownLedgerOnlyShrinks makes reviewedAmbientHTTPClients a
// ratchet. The rule landed pre-sized to the ambient client sites that already
// existed, so `make lint` stayed green on day one; from here the ledger may only
// get smaller. New outbound code takes its client from netsec or egress.
func TestAmbientHTTPBurnDownLedgerOnlyShrinks(t *testing.T) {
	const sizeWhenTheRuleLanded = 27
	total := 0
	for _, functions := range reviewedAmbientHTTPClients {
		total += len(functions)
	}
	if total > sizeWhenTheRuleLanded {
		t.Fatalf("reviewedAmbientHTTPClients holds %d reviewed sites, more than the %d it landed with; SEC-005 debt may only shrink -- route the new call site through internal/netsec or egress.Guard instead of adding a row", total, sizeWhenTheRuleLanded)
	}
}

// TestAmbientHTTPBurnDownLedgerKeepsTheMigratedSitesOut is the second half of the
// ratchet. TestAmbientHTTPBurnDownLedgerOnlyShrinks bounds the TOTAL; this one
// pins the specific call sites that have already been migrated to
// netsec.SafeClient / netsec.InsecureLoopbackClient, so a later change cannot
// silently re-introduce an ambient client at a site whose debt was already paid
// and stay under the total. It also pins the post-migration total, so the ledger
// cannot creep back up toward 27.
func TestAmbientHTTPBurnDownLedgerKeepsTheMigratedSitesOut(t *testing.T) {
	const sizeAfterTheFirstBurnDown = 20
	migrated := []string{
		"internal/agent/httpenroll.go",
		"internal/discovery/ctmonitor/httpfetcher.go",
		"internal/perf/live.go",
		"internal/protocols/acme/validate.go",
		"internal/protocols/ari/client.go",
		"tools/pqclab/main.go",
	}
	for _, file := range migrated {
		if functions, ok := reviewedAmbientHTTPClients[file]; ok {
			t.Errorf("%s was migrated off ambient http.Client construction but is back in the burn-down ledger as %#v; take its client from internal/netsec instead of re-adding the row", file, functions)
		}
	}
	total := 0
	for _, functions := range reviewedAmbientHTTPClients {
		total += len(functions)
	}
	if total != sizeAfterTheFirstBurnDown {
		t.Fatalf("reviewedAmbientHTTPClients holds %d reviewed sites, want exactly %d after the first burn-down pass; lower this constant when you migrate another site, never raise it", total, sizeAfterTheFirstBurnDown)
	}
}

// TestBasePackagePathStripsTestVariantSuffix covers the trap that would have
// broken `make lint`: `go vet` analyzes a package a second time as part of its
// own test binary, under the import path "p [p.test]". Without the strip,
// internal/netsec would lose its guard exemption in that pass and report on its
// own SafeClient constructor.
func TestBasePackagePathStripsTestVariantSuffix(t *testing.T) {
	const plain = "trstctl.com/trstctl/internal/netsec"
	if got := basePackagePath(plain + " [" + plain + ".test]"); got != plain {
		t.Fatalf("basePackagePath(test variant) = %q, want %q", got, plain)
	}
	if got := basePackagePath(plain); got != plain {
		t.Fatalf("basePackagePath(plain) = %q, want %q", got, plain)
	}
}
