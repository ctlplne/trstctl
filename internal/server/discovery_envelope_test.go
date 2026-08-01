// SPDX-License-Identifier: MPL-2.0

package server

import (
	"testing"

	"trstctl.com/trstctl/internal/cbom/coverage"
)

// TestEveryDiscoverySourceDeclaresEnvelope welds the served discovery-source
// catalog (the executor registry — the kinds this server can actually run) to
// the observability-envelope registry in internal/cbom/coverage, in both
// directions: a served kind with no envelope means the system cannot say what
// that source can and cannot see, and an envelope naming an unserved kind is
// a phantom declaration. Either direction fails the build — modelled on
// TestEveryTenantTableForcesRLS: catalog-derived, never a hand-typed list.
func TestEveryDiscoverySourceDeclaresEnvelope(t *testing.T) {
	kinds := servedDiscoverySourceKinds()
	// Vacuity floor: the registry replaced a 15-kind dispatch chain; finding
	// far fewer means the derivation broke, not that the product shrank.
	if len(kinds) < 10 {
		t.Fatalf("served source catalog has only %d kinds (%v); the executor registry is not being derived", len(kinds), kinds)
	}

	envs := coverage.Envelopes()
	for _, kind := range kinds {
		if _, ok := envs[kind]; !ok {
			t.Errorf("served discovery source kind %q declares no observability envelope; add it to coverage.Envelopes() so the system can say what this source can and cannot see", kind)
		}
	}
	for kind := range envs {
		if kind == coverage.ManualKind {
			continue // the fallback for kinds with no dedicated connector
		}
		if _, served := discoveryRunExecutors[kind]; !served {
			t.Errorf("coverage.Envelopes() declares an envelope for %q, but the server has no executor for that kind; a phantom envelope overstates coverage", kind)
		}
	}
}
