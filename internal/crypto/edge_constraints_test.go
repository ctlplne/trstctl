// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"net"
	"strings"
	"testing"
	"time"
)

var edgeNow = time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)

func edgeCA(permitted ...string) EdgeConstraints {
	return EdgeConstraints{
		PermittedDNSDomains: permitted,
		NotAfter:            edgeNow.Add(7 * 24 * time.Hour),
	}
}

// The classic name-constraint bypass: "corp.example" must not permit
// "evilcorp.example". A strings.HasSuffix at a call site gets this wrong, and
// the result is a delegated CA that can impersonate a domain it was never
// scoped to.
func TestAConstraintMatchesOnLabelBoundariesNotSuffixes(t *testing.T) {
	t.Parallel()
	c := edgeCA("corp.example")
	if err := CheckEdgeIssuance(c, []string{"host.corp.example"}, nil, edgeNow); err != nil {
		t.Fatalf("a legitimate subdomain was refused: %v", err)
	}
	if err := CheckEdgeIssuance(c, []string{"corp.example"}, nil, edgeNow); err != nil {
		t.Fatalf("the constrained domain itself was refused: %v", err)
	}
	if err := CheckEdgeIssuance(c, []string{"evilcorp.example"}, nil, edgeNow); err == nil {
		t.Fatal("\"evilcorp.example\" was permitted by a constraint of \"corp.example\".\n\n" +
			"That is the classic name-constraint bypass: a suffix match without a label boundary " +
			"lets a delegated edge CA impersonate any domain that happens to end with the " +
			"permitted string.")
	}
}

// An unconstrained delegated CA must be refused outright — it is a worse
// failure than a request that asked for too much.
func TestAnUnconstrainedEdgeCAIsRefusedBeforeAnyNameIsChecked(t *testing.T) {
	t.Parallel()
	err := CheckEdgeIssuance(EdgeConstraints{NotAfter: edgeNow.Add(time.Hour)},
		[]string{"anything.example"}, nil, edgeNow)
	if err == nil {
		t.Fatal("a delegated CA with NO name constraints issued a certificate.\n\n" +
			"An empty permitted set must mean NOTHING is permitted. Reading it as \"anything\" " +
			"produces an unbounded CA on a host nobody can reach — the shadow CA this whole " +
			"design exists to prevent.")
	}
	if !strings.Contains(err.Error(), "unbounded shadow CA") {
		t.Errorf("the error does not explain the risk: %v", err)
	}
}

// Exclusion beats permission. An operator who excluded a name meant it.
func TestAnExclusionCannotBeReAdmittedByABroaderPermission(t *testing.T) {
	t.Parallel()
	c := EdgeConstraints{
		PermittedDNSDomains: []string{"corp.example"},
		ExcludedDNSDomains:  []string{"secret.corp.example"},
		NotAfter:            edgeNow.Add(time.Hour),
	}
	if err := CheckEdgeIssuance(c, []string{"host.secret.corp.example"}, nil, edgeNow); err == nil {
		t.Fatal("an excluded subtree was issued because a broader suffix permitted it.\n\n" +
			"Exclusion must win: otherwise every exclusion is undone by the permission that " +
			"made the exclusion necessary in the first place.")
	}
	if err := CheckEdgeIssuance(c, []string{"host.corp.example"}, nil, edgeNow); err != nil {
		t.Fatalf("a permitted, non-excluded name was refused: %v", err)
	}
}

// A delegated CA that keeps issuing past its own expiry is a permanent CA.
func TestAnExpiredEdgeCACannotIssue(t *testing.T) {
	t.Parallel()
	c := edgeCA("corp.example")
	after := c.NotAfter.Add(time.Second)
	if err := CheckEdgeIssuance(c, []string{"host.corp.example"}, nil, after); err == nil {
		t.Fatal("an expired delegated CA issued a certificate.\n\n" +
			"The short validity IS the bound that makes delegating a signing key defensible. A " +
			"CA that keeps working past it is a permanent CA on an unreachable host.")
	}
}

// Case and a trailing dot must not create two different names, one permitted
// and one not.
func TestNameMatchingIsCaseAndTrailingDotInsensitive(t *testing.T) {
	t.Parallel()
	c := edgeCA("corp.example")
	for _, name := range []string{"HOST.CORP.EXAMPLE", "host.corp.example.", "Host.Corp.Example."} {
		if err := CheckEdgeIssuance(c, []string{name}, nil, edgeNow); err != nil {
			t.Errorf("%q was refused: %v. Case and a trailing dot are the same name, and treating "+
				"them differently means a constraint can be evaded by typing it differently", name, err)
		}
	}
	// The bypass must stay closed under the same normalization.
	if err := CheckEdgeIssuance(c, []string{"EVILCORP.EXAMPLE"}, nil, edgeNow); err == nil {
		t.Fatal("normalization re-opened the suffix bypass")
	}
}

// A certificate naming nothing cannot be checked against a constraint, so it
// must not be issued.
func TestAnIssuanceWithNoNamesIsRefused(t *testing.T) {
	t.Parallel()
	if err := CheckEdgeIssuance(edgeCA("corp.example"), nil, nil, edgeNow); err == nil {
		t.Fatal("a certificate with no names was issued. There is nothing to check it against, " +
			"so permitting it means the constraint did not apply at all")
	}
}

// IP SANs are constrained too, and an empty permitted range set permits none.
func TestIPSANsAreConstrainedAndEmptyPermitsNone(t *testing.T) {
	t.Parallel()
	_, netA, _ := net.ParseCIDR("10.1.0.0/16")
	c := EdgeConstraints{PermittedIPRanges: []*net.IPNet{netA}, NotAfter: edgeNow.Add(time.Hour)}
	if err := CheckEdgeIssuance(c, nil, []net.IP{net.ParseIP("10.1.2.3")}, edgeNow); err != nil {
		t.Fatalf("an in-range IP SAN was refused: %v", err)
	}
	if err := CheckEdgeIssuance(c, nil, []net.IP{net.ParseIP("10.2.2.3")}, edgeNow); err == nil {
		t.Fatal("an out-of-range IP SAN was issued")
	}
	// A DNS-only CA must not silently permit IP SANs.
	if err := CheckEdgeIssuance(edgeCA("corp.example"), nil, []net.IP{net.ParseIP("10.1.2.3")}, edgeNow); err == nil {
		t.Fatal("a CA constrained only by DNS issued an IP SAN. An IP SAN nobody scoped is a " +
			"name the delegation never covered")
	}
}

// A leaf must never outlive the CA that issued it.
func TestALeafNeverOutlivesItsDelegatedCA(t *testing.T) {
	t.Parallel()
	c := edgeCA("corp.example")
	requested := c.NotAfter.Add(30 * 24 * time.Hour)
	if got := EdgeLeafNotAfter(c, requested); got.After(c.NotAfter) {
		t.Fatalf("leaf NotAfter = %v, past the CA's %v.\n\n"+
			"Such a leaf validates today and fails the moment the CA expires, with nothing in it "+
			"explaining why — on a host nobody can reach to fix it.", got, c.NotAfter)
	}
	shorter := c.NotAfter.Add(-time.Hour)
	if got := EdgeLeafNotAfter(c, shorter); !got.Equal(shorter) {
		t.Fatalf("a shorter requested lifetime was extended to %v", got)
	}
}
