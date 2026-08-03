// SPDX-License-Identifier: MPL-2.0

package docs

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/agent/discovery"
	"trstctl.com/trstctl/internal/agent/relay"
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
	// Every declared kind now has a reader (C1 complete): k8s-secret, then
	// windows-store, then pkcs11. What this test protects is no longer a list of
	// unbuilt kinds but the rule that produced it — advertised must equal
	// shipped, for THIS binary.
	//
	// pkcs11 is the case that makes the rule sharp. It needs cgo to dlopen a
	// vendor module, and the default agent build is deliberately cgo-free, so
	// whether it ships depends on how the binary was built. The census is
	// build-dependent for exactly that reason, and the assertion is that the two
	// agree — not that pkcs11 is or is not present.
	missing := discovery.UnshippedSourceKinds()
	for _, kind := range missing {
		if discovery.IsShippedSourceKind(kind) {
			t.Errorf("source kind %q is reported both shipped and unshipped", kind)
		}
	}
	if len(missing) > 0 && !containsString(missing, "pkcs11") {
		t.Errorf("unshipped kinds %v include something other than the cgo-gated pkcs11; a kind that lost its reader is a regression", missing)
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

// TestShippedRelayJobKindsAreExecutableByTheBinary applies the C1a contract to
// the relay runtime (epic A3).
//
// It bites harder here than for discovery. A discovery kind advertised but not
// shipped merely fails to collect something. A relay JOB kind advertised but not
// executable takes a claim, burns the attempt's one credential redemption —
// moving material outside the seal for nothing — and hands the work back, while
// the queue looks like it is being served.
func TestShippedRelayJobKindsAreExecutableByTheBinary(t *testing.T) {
	t.Parallel()
	shipped := relay.ShippedJobKinds()
	if len(shipped) == 0 {
		t.Fatal("relay declares no shipped job kinds; the census must be explicit, not empty by accident")
	}
	sources := readAgentBinarySources(t)
	for _, kind := range shipped {
		if len(kind.Connectors) == 0 {
			t.Errorf("relay job kind %q declares no connectors; a kind with no executor is not shipped", kind.Kind)
		}
		// The binary must actually run the loop for a declared kind, not merely
		// link the package.
		if !strings.Contains(sources, "relay.RunOnce(") {
			t.Errorf("relay job kind %q is declared but the agent binary never calls relay.RunOnce", kind.Kind)
		}
		for _, connectorName := range kind.Connectors {
			if !relay.Executes(connectorName) {
				t.Errorf("relay job kind %q declares connector %q, which the executor refuses", kind.Kind, connectorName)
			}
		}
	}
	// Every unshipped kind must carry a reason. "It does not work yet" is a
	// sentence an operator can act on; silence is not.
	for kind, reason := range relay.UnshippedJobKinds() {
		if strings.TrimSpace(reason) == "" {
			t.Errorf("unshipped relay job kind %q has no reason recorded", kind)
		}
		for _, s := range shipped {
			if s.Kind == kind {
				t.Errorf("job kind %q is listed as both shipped and unshipped", kind)
			}
		}
	}
}

// readAgentBinarySources concatenates the agent binary's sources so a test can
// assert what the binary actually calls, not merely what it could.
func readAgentBinarySources(t *testing.T) string {
	t.Helper()
	var b strings.Builder
	for _, dir := range agentBinarySources {
		root := filepath.Join("..", dir)
		if err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			// #nosec G304,G122 -- repo-relative walk of this repository's own
			// committed source in a test; there is no attacker-controlled path
			// and no symlink race to lose (CWE-22).
			data, readErr := os.ReadFile(path)
			if readErr != nil {
				return readErr
			}
			b.Write(data)
			return nil
		}); err != nil {
			t.Fatalf("walk %s: %v", root, err)
		}
	}
	return b.String()
}
