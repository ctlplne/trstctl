// SPDX-License-Identifier: MPL-2.0

package docs

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/agent/discovery"
)

// Advertised agent capability must equal shipped agent capability
// (truth-integrity 1, epic C1's P0 half).
//
// GET /api/v1/agents advertised seven discovery source kinds on every enrolled
// agent from a hardcoded list. The agent binary builds enumerators for four of
// them. An operator reading that panel concluded their Windows certificate store,
// their PKCS#11 tokens, and their Kubernetes Secrets were being inventoried; none
// of the three has an enumerator in the binary at all.
//
// The list now comes from discovery.ShippedSourceKinds. These tests keep it
// honest from both directions: every advertised kind has a constructor the agent
// binary actually calls, and the kinds known to be missing stay off the list until
// they are built.

// agentBinarySources are the files that make up the shipped agent's collection
// path. A constructor counts as reached if one of these calls it.
var agentBinarySources = []string{
	"cmd/trstctl-agent/",
	"internal/agent/",
}

// TestAdvertisedAgentSourcesHaveAConstructorInTheBinary is the contract: a kind
// may not be advertised unless the agent binary constructs its enumerator.
func TestAdvertisedAgentSourcesHaveAConstructorInTheBinary(t *testing.T) {
	t.Parallel()
	shipped := discovery.ShippedSourceKinds()
	if len(shipped) == 0 {
		t.Fatal("no shipped agent source kinds declared; the agent collects something, so this list has drifted")
	}

	body := agentBinaryText(t)
	for _, s := range shipped {
		if s.Kind == "" {
			t.Error("a shipped source kind has an empty kind")
			continue
		}
		if s.Constructor == "" {
			t.Errorf("shipped source %q names no constructor, so nothing proves the agent can collect it", s.Kind)
			continue
		}
		if !strings.Contains(body, s.Constructor+"(") {
			t.Errorf("shipped source %q claims constructor %q, but no file under %s calls it — either wire the enumerator or stop advertising the kind",
				s.Kind, s.Constructor, strings.Join(agentBinarySources, ", "))
		}
	}
}

// TestUnshippedAgentSourcesAreNotAdvertised pins the three kinds the gap analysis
// found being advertised without an implementation. Each returns to the shipped
// list only when epic C1 actually builds it.
func TestUnshippedAgentSourcesAreNotAdvertised(t *testing.T) {
	t.Parallel()
	// k8s-secret left this list when its enumerator was actually wired into the
	// agent binary (C1). PKCS#11 and the Windows certificate store have no read
	// path yet, so they stay off the advertised set until they do.
	for _, kind := range []string{"pkcs11", "windows-store"} {
		if discovery.IsShippedSourceKind(kind) {
			// Not a failure to be silenced: if the enumerator is genuinely wired
			// now, delete the kind from this list in the same change.
			t.Errorf("source kind %q is advertised as shipped; if its enumerator is now wired into the agent binary, remove it from this test's list in the same change",
				kind)
		}
	}
	missing := discovery.UnshippedSourceKinds()
	if len(missing) == 0 {
		t.Log("every declared source kind now ships; epic C1 is complete and this test can be retired")
	}
}

// TestLimitationsRecordsUnshippedAgentSources keeps the served-state page naming
// the gap, so an evaluator reads it there rather than discovering it from an
// empty inventory.
func TestLimitationsRecordsUnshippedAgentSources(t *testing.T) {
	t.Parallel()
	limitations := read(t, "limitations.md")
	for _, kind := range discovery.UnshippedSourceKinds() {
		if !strings.Contains(limitations, kind) {
			t.Errorf("docs/limitations.md must name the unshipped agent source kind %q; advertising minus documentation is how it went unnoticed", kind)
		}
	}
}

func agentBinaryText(t *testing.T) string {
	t.Helper()
	var b strings.Builder
	for _, rel := range gitTrackedFiles(t) {
		if !strings.HasSuffix(rel, ".go") || strings.HasSuffix(rel, "_test.go") {
			continue
		}
		if !hasAnyPrefix(rel, agentBinarySources) {
			continue
		}
		body, err := os.ReadFile(filepath.Join("..", filepath.FromSlash(rel)))
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			t.Fatalf("agent capability gate: read %s: %v", rel, err)
		}
		b.Write(body)
		b.WriteByte('\n')
	}
	if b.Len() == 0 {
		t.Fatal("agent capability gate found no agent source files; the scan list has drifted from the tree")
	}
	return b.String()
}
