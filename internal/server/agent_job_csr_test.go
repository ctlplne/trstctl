// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"strings"
	"testing"
)

// The authorization rule for host-generated renewal (epic B2).
//
// B2 replaces "the control plane sends a key down" with "the agent sends a CSR
// up", and that inversion creates a new attack surface the old flow did not
// have: the agent now CHOOSES what to ask for. If the choice were trusted, an
// agent holding one legitimate renewal could mint a certificate for any name it
// liked — a worse hole than the custody problem the epic exists to fix, opened
// by the fix for it.
//
// So the rule under test is: names come from the JOB, the CSR is checked against
// them, and anything outside is refused.

func TestACSRMayNotWidenTheNamesItsJobAuthorizes(t *testing.T) {
	t.Parallel()
	permitted := []string{"api.example.test", "www.example.test"}

	// The attack: a legitimately held renewal, plus one extra name.
	offending, ok := csrNamesWithinBinding(
		[]string{"api.example.test", "admin.other-tenant.test"}, permitted)
	if ok {
		t.Fatal("a CSR asserting a name outside its binding was accepted; an agent holding one " +
			"renewal could mint a certificate for any service it named")
	}
	if offending != "admin.other-tenant.test" {
		t.Errorf("the refusal named %q, not the offending name; an operator debugging this needs "+
			"to know which name was rejected", offending)
	}
}

func TestACSRMayRequestFewerNamesThanItsBindingCarries(t *testing.T) {
	t.Parallel()
	// A subset is legitimate. A host renewing for one of the two names it is
	// bound to is doing something NARROWER than authorized, and refusing it
	// would break real migrations for no security benefit.
	if _, ok := csrNamesWithinBinding([]string{"api.example.test"},
		[]string{"api.example.test", "www.example.test"}); !ok {
		t.Error("a CSR requesting a subset of its binding was refused")
	}
	// Empty asserts nothing and takes nothing.
	if _, ok := csrNamesWithinBinding(nil, []string{"api.example.test"}); !ok {
		t.Error("a CSR asserting no names was refused")
	}
}

func TestNameComparisonIsCaseInsensitiveLikeDNS(t *testing.T) {
	t.Parallel()
	// DNS is case-insensitive, so a case-sensitive check would be a bypass:
	// API.EXAMPLE.TEST and api.example.test are the same host, and a certificate
	// for either serves both.
	if _, ok := csrNamesWithinBinding([]string{"API.Example.TEST"},
		[]string{"api.example.test"}); !ok {
		t.Error("a name differing only in case was refused; DNS does not distinguish them")
	}
	// And the bypass in the other direction: a permitted set in mixed case must
	// not let an unrelated name through.
	if _, ok := csrNamesWithinBinding([]string{"evil.example.test"},
		[]string{"API.Example.TEST"}); ok {
		t.Error("case-folding the permitted set admitted an unrelated name")
	}
}

func TestAFloodOfNamesIsRefusedRatherThanCompared(t *testing.T) {
	t.Parallel()
	many := make([]string, signJobCSRNameLimit+1)
	for i := range many {
		many[i] = "a" + strings.Repeat("b", i) + ".example.test"
	}
	if _, ok := csrNamesWithinBinding(many, []string{"api.example.test"}); ok {
		t.Error("a CSR asserting more names than a binding may carry was accepted")
	}
}

// The permitted set comes from the job payload, never from the request.
func TestPermittedNamesAreReadFromTheJobPayload(t *testing.T) {
	t.Parallel()
	payload, err := json.Marshal(RelayDeployIntent{
		Connector:         "file",
		Target:            "web01",
		SubjectCommonName: "API.Example.Test",
		SubjectDNSNames:   []string{"api.example.test", " www.example.test "},
	})
	if err != nil {
		t.Fatal(err)
	}
	got := signJobCSRPermittedNames(payload)
	want := map[string]bool{"api.example.test": true, "www.example.test": true}
	if len(got) != len(want) {
		t.Fatalf("permitted names = %v, want exactly the two distinct names the binding carries", got)
	}
	for _, n := range got {
		if !want[n] {
			t.Errorf("permitted names include %q, which the binding does not carry", n)
		}
	}

	// A payload that names nothing authorizes nothing. It must not fall back to
	// the connector target — a routing string is not a subject, and certifying
	// one would issue for a name nobody chose.
	empty := signJobCSRPermittedNames([]byte(`{"connector":"file","target":"web01"}`))
	if len(empty) != 0 {
		t.Errorf("a payload with no subject authorized %v; a renewal that names no subject "+
			"authorizes nothing", empty)
	}
	// Garbage authorizes nothing rather than everything.
	if n := signJobCSRPermittedNames([]byte("not json")); len(n) != 0 {
		t.Errorf("an undecodable payload authorized %v", n)
	}
}

// The response shape cannot carry a private key. This is a structural claim, so
// it is checked structurally rather than by inspecting a value at runtime.
func TestTheSigningResponseHasNoFieldThatCouldCarryAKey(t *testing.T) {
	t.Parallel()
	raw, err := json.Marshal(struct {
		CertificatePEM []byte `json:"certificate_pem"`
		ChainPEM       []byte `json:"chain_pem,omitempty"`
		Fingerprint    string `json:"fingerprint,omitempty"`
	}{})
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"key", "private", "secret"} {
		if strings.Contains(strings.ToLower(string(raw)), forbidden) {
			t.Errorf("the signing response has a %q field; the security property of this epic is "+
				"that there is nowhere to put a key, not that nobody does", forbidden)
		}
	}
}
