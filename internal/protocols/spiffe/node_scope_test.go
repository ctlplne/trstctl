// SPDX-License-Identifier: BUSL-1.1

package spiffe

import (
	"context"
	"errors"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
)

// Node scoping is what bounds an agent's claim (epic B3).
//
// Moving the Workload API onto hosts means selectors arrive as an AGENT'S CLAIM
// about a process it inspected on another machine. Nothing the control plane can
// see verifies that claim and nothing could. So the control plane does not try:
// it bounds what the claim can unlock, by scoping each registration entry to the
// node permitted to deliver it.
//
// Without that bound, one compromised host agent could assert any selectors and
// obtain any workload's identity in the trust domain — a compromise of one
// machine becoming a compromise of every service. These tests hold the bound.

func nodeScopeServer(t *testing.T, entries ...RegistrationEntry) *Server {
	t.Helper()
	wl, err := New(Config{
		Issuer: testIssuer(t), TenantID: "tenant-a", TrustDomain: "example.org",
		Entries: entries,
	})
	if err != nil {
		t.Fatal(err)
	}
	return wl
}

func TestAnAgentCannotFetchAnotherNodesWorkloadIdentity(t *testing.T) {
	t.Parallel()
	const (
		nodeA = "spiffe://example.org/agent/host-a"
		nodeB = "spiffe://example.org/agent/host-b"
	)
	wl := nodeScopeServer(t, RegistrationEntry{
		SPIFFEID: "spiffe://example.org/payments", Selectors: []string{"unix:uid:0"},
		ParentID: nodeA,
	})
	pub := testPublicKeyDER(t)

	// The node the entry names gets it.
	got, err := wl.FetchX509SVIDsForNode(context.Background(), nodeA, pub, []string{"unix:uid:0"})
	if err != nil {
		t.Fatalf("the entry's own node was refused its identity: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("issued %d SVIDs to the entry's node, want 1", len(got))
	}

	// A DIFFERENT node presenting the identical selectors gets nothing. This is
	// the whole property: selectors are a claim, and the claim only unlocks what
	// the claiming node was scoped to.
	_, err = wl.FetchX509SVIDsForNode(context.Background(), nodeB, pub, []string{"unix:uid:0"})
	if !errors.Is(err, ErrNoIdentity) {
		t.Fatalf("a different node obtained another host's workload identity (err=%v); one "+
			"compromised agent would become a compromise of every service in the trust domain", err)
	}
}

func TestAnUnscopedEntryIsNotDeliverableByAnyAgent(t *testing.T) {
	t.Parallel()
	// No ParentID. Reachable on the control plane's own socket, as before this
	// epic — and reachable by NO agent, because an operator has not said which
	// node may deliver it. Absent must never read as "any".
	wl := nodeScopeServer(t, RegistrationEntry{
		SPIFFEID: "spiffe://example.org/legacy", Selectors: []string{"unix"},
	})
	pub := testPublicKeyDER(t)

	if _, err := wl.FetchX509SVIDsForNode(context.Background(),
		"spiffe://example.org/agent/host-a", pub, []string{"unix"}); !errors.Is(err, ErrNoIdentity) {
		t.Fatalf("an agent obtained an entry no operator scoped to it (err=%v); a forgotten "+
			"ParentID would silently widen who can impersonate this workload", err)
	}

	// The local socket still serves it, unchanged.
	got, err := wl.FetchX509SVIDs(context.Background(), pub, []string{"unix"})
	if err != nil {
		t.Fatalf("the control plane's own socket stopped serving an existing entry: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("local socket issued %d SVIDs, want 1", len(got))
	}
}

func TestAScopedEntryLeavesTheLocalSocketWhenItMoves(t *testing.T) {
	t.Parallel()
	const node = "spiffe://example.org/agent/host-a"
	wl := nodeScopeServer(t, RegistrationEntry{
		SPIFFEID: "spiffe://example.org/moved", Selectors: []string{"unix"},
		ParentID: node,
	})
	pub := testPublicKeyDER(t)

	// Scoping an entry to a node MOVES it. It stops being served locally at the
	// same moment it starts being served on the host, so an operator can see the
	// migration happen rather than having to believe it did.
	if _, err := wl.FetchX509SVIDs(context.Background(), pub, []string{"unix"}); !errors.Is(err, ErrNoIdentity) {
		t.Errorf("a node-scoped entry was still served on the control plane's socket (err=%v); "+
			"an entry reachable from both places makes the migration unobservable", err)
	}
	if _, err := wl.FetchX509SVIDsForNode(context.Background(), node, pub, []string{"unix"}); err != nil {
		t.Errorf("the scoped entry was not served to its own node: %v", err)
	}
}

// An empty node must not fall through to the unscoped entries.
func TestAnUnidentifiedNodeIsRefusedRatherThanDefaulted(t *testing.T) {
	t.Parallel()
	wl := nodeScopeServer(t, RegistrationEntry{
		SPIFFEID: "spiffe://example.org/legacy", Selectors: []string{"unix"},
	})
	if _, err := wl.FetchX509SVIDsForNode(context.Background(), "", testPublicKeyDER(t),
		[]string{"unix"}); !errors.Is(err, ErrNoIdentity) {
		t.Fatalf("a caller that could not identify its node reached the unscoped entries "+
			"(err=%v); those are reserved for the control plane's own socket", err)
	}
}

// testPublicKeyDER is a fresh workload public key.
//
// A real generated key, not a fixture: the SVID is signed over it, and a shared
// constant would let a test pass that should have caught a path binding the
// wrong key.
func testPublicKeyDER(t *testing.T) []byte {
	t.Helper()
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Destroy)
	return key.Public().DER
}
