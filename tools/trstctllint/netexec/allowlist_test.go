// SPDX-License-Identifier: BUSL-1.1

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

func TestReviewedExecAllowlistPinsEmbeddedPostgres(t *testing.T) {
	want := map[string]map[string]bool{
		"third_party/embedded-postgres/embedded_postgres.go": {
			"startPostgres": true,
			"stopPostgres":  true,
		},
		"third_party/embedded-postgres/prepare_database.go": {
			"defaultInitDatabase": true,
		},
		"third_party/embedded-postgres/version_strategy.go": {
			"linuxMachineName": true,
		},
	}
	for file, functions := range want {
		if got := reviewedExecUses[file]; !reflect.DeepEqual(got, functions) {
			t.Fatalf("%s reviewed exec allowlist = %#v, want %#v", file, got, functions)
		}
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
// permanentAmbientHTTPClients are reviewed sites that are NOT burn-down
// candidates, because no policy-bearing client from internal/netsec can serve
// them.
//
// Exactly one so far. A relay's whole purpose is reaching devices on private,
// non-routable addresses inside its own segment — the destinations the control
// plane's egress guard and SSRF transport exist to refuse. netsec offers a
// loopback client and an origin-bound transport; neither fits, and forcing one
// would either break the relay or dilute the guard for everything else.
//
// Named rather than counted. Simply raising the burn-down number for this would
// have hidden a permanent exception inside a total that is supposed to fall,
// and the next person would have had no way to tell the two apart.
var permanentAmbientHTTPClients = map[string]map[string]bool{
	"cmd/trstctl-agent/relayloop.go": {"relayHTTPClient": true},
}

func TestAmbientHTTPBurnDownLedgerKeepsTheMigratedSitesOut(t *testing.T) {
	// 20 after the first burn-down pass; 19 since 2026-09-20, when the Terraform
	// provider (internal/terraformprovider/client.go:NewClient) left the root
	// module for the MPL-2.0 clients/terraform module, outside this analyzer's
	// scope. That site was not migrated: it still builds its own http.Client, and
	// the ledger only counts sites the analyzer can see.
	const sizeAfterTheFirstBurnDown = 19
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
	// Every permanent exception must actually be in the ledger — an exemption
	// for a site that no longer exists is a hole waiting for a future function
	// of the same name.
	for file, functions := range permanentAmbientHTTPClients {
		for fn := range functions {
			if !reviewedAmbientHTTPClients[file][fn] {
				t.Errorf("%s:%s is exempted from the burn-down but is not in the reviewed ledger; "+
					"remove the exemption when the site goes", file, fn)
			}
		}
	}
	total := 0
	for file, functions := range reviewedAmbientHTTPClients {
		for fn := range functions {
			if permanentAmbientHTTPClients[file][fn] {
				continue
			}
			total++
		}
	}
	if total != sizeAfterTheFirstBurnDown {
		t.Fatalf("reviewedAmbientHTTPClients holds %d migratable reviewed sites, want exactly %d after "+
			"the first burn-down pass; lower this constant when you migrate another site, never raise "+
			"it. A site that genuinely cannot take a netsec client belongs in "+
			"permanentAmbientHTTPClients with its reason, not in this total", total, sizeAfterTheFirstBurnDown)
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
