// SPDX-License-Identifier: BUSL-1.1

package acme

import (
	"testing"
	"time"
)

var eabNow = time.Date(2026, 8, 3, 0, 0, 0, 0, time.UTC)

// TestEABPolicyPermitsScopesWithoutSurprises pins the matcher. Getting this
// subtly wrong is worse than having no scope at all: an operator who writes
// "*.example.com" and gets silent over-matching believes they are constrained
// when they are not.
func TestEABPolicyPermitsScopesWithoutSurprises(t *testing.T) {
	scoped := EABPolicy{AllowedIdentifiers: []string{"*.payments.example.test", "fixed.example.test"}}
	cases := []struct {
		identifier string
		want       bool
		why        string
	}{
		{"api.payments.example.test", true, "a label under the granted suffix"},
		{"a.b.payments.example.test", true, "any depth under the granted suffix"},
		{"payments.example.test", true, "the apex of the granted suffix, which is what an operator means by *.x"},
		{"API.Payments.Example.Test", true, "DNS names are case-insensitive"},
		{"api.payments.example.test.", true, "a trailing dot is the same name"},
		{"fixed.example.test", true, "an exact entry matches itself"},
		{"sub.fixed.example.test", false, "an exact entry is not a suffix rule"},
		{"billing.example.test", false, "a sibling zone is outside the grant"},
		{"evilpayments.example.test", false, "suffix matching must not match a label boundary that is not there"},
		{"example.test", false, "the parent of the granted suffix is outside it"},
		{"", false, "an empty identifier is not inside any scope"},
	}
	for _, tc := range cases {
		if got := scoped.permits(tc.identifier); got != tc.want {
			t.Errorf("permits(%q) = %v, want %v — %s", tc.identifier, got, tc.want, tc.why)
		}
	}

	if !(EABPolicy{}).permits("anything.example.test") {
		t.Error("a credential with no allowed identifiers must stay unscoped; adding scope is opt-in")
	}
	// An empty entry must not quietly widen a scope that looks narrow. Config
	// validation rejects it too; this is the second line of defense.
	narrow := EABPolicy{AllowedIdentifiers: []string{"", "fixed.example.test"}}
	if narrow.permits("anything.example.test") {
		t.Error("an empty entry must not act as a wildcard")
	}
}

func TestEABPolicyWindow(t *testing.T) {
	if (EABPolicy{}).expired(eabNow) {
		t.Error("a credential with no window never expires")
	}
	if !(EABPolicy{NotAfter: eabNow.Add(-time.Second)}).expired(eabNow) {
		t.Error("a credential past its not_after is expired")
	}
	if (EABPolicy{NotAfter: eabNow.Add(time.Second)}).expired(eabNow) {
		t.Error("a credential inside its window is not expired")
	}
	if !(EABPolicy{NotAfter: eabNow}).expired(eabNow) {
		t.Error("not_after is exclusive: at the instant itself the window has closed")
	}
}

// TestEABCredentialActiveNamesTheCause covers the four ways a credential stops
// admitting work. The reason travels into the ACME problem document, so a client
// operator can tell "your credential is switched off" from "your credential has
// run out" without asking anyone.
func TestEABCredentialActiveNamesTheCause(t *testing.T) {
	t.Run("config disable outranks everything", func(t *testing.T) {
		c := &eabCredential{policy: EABPolicy{Disabled: true}}
		ok, reason := c.active(eabNow)
		if ok || reason != "external account credential is disabled in configuration" {
			t.Fatalf("active = %v %q", ok, reason)
		}
	})
	t.Run("operator disable", func(t *testing.T) {
		c := &eabCredential{disabledByOperator: true}
		ok, reason := c.active(eabNow)
		if ok || reason != "external account credential has been disabled by an operator" {
			t.Fatalf("active = %v %q", ok, reason)
		}
	})
	t.Run("closed window", func(t *testing.T) {
		c := &eabCredential{policy: EABPolicy{NotAfter: eabNow.Add(-time.Hour)}}
		ok, reason := c.active(eabNow)
		if ok || reason != "external account credential's validity window has closed" {
			t.Fatalf("active = %v %q", ok, reason)
		}
	})
	t.Run("quota reached", func(t *testing.T) {
		c := &eabCredential{policy: EABPolicy{MaxOrders: 2}, ordersCreated: 2}
		ok, reason := c.active(eabNow)
		if ok || reason != "external account credential has reached its order quota" {
			t.Fatalf("active = %v %q", ok, reason)
		}
	})
	t.Run("healthy", func(t *testing.T) {
		c := &eabCredential{policy: EABPolicy{MaxOrders: 2}, ordersCreated: 1}
		if ok, reason := c.active(eabNow); !ok || reason != "" {
			t.Fatalf("active = %v %q", ok, reason)
		}
	})
}

// TestSetEABDisabledCannotLiftTheConfigurationFloor is the safety property of the
// runtime verb: an API call may switch a credential off, never on past config.
func TestSetEABDisabledCannotLiftTheConfigurationFloor(t *testing.T) {
	s := New(nil, Validators{})
	s.eabCredentials = map[string]*eabCredential{
		"locked": {keyID: "locked", policy: EABPolicy{Disabled: true}},
		"normal": {keyID: "normal"},
	}

	status, ok := s.SetEABDisabled("locked", false)
	if !ok {
		t.Fatal("SetEABDisabled did not find a configured credential")
	}
	if status.State != "disabled" {
		t.Fatalf("a config-disabled credential was re-enabled by an API call: %+v", status)
	}

	if status, ok = s.SetEABDisabled("normal", true); !ok || status.State != "disabled" || !status.DisabledByOperator {
		t.Fatalf("disable did not take effect: ok=%v %+v", ok, status)
	}
	if status, ok = s.SetEABDisabled("normal", false); !ok || status.State != "active" || status.DisabledByOperator {
		t.Fatalf("enable did not take effect: ok=%v %+v", ok, status)
	}
	if _, ok = s.SetEABDisabled("no-such-kid", true); ok {
		t.Error("SetEABDisabled reported success for a credential that is not configured")
	}
}

// TestEABCredentialsCarryNoSecret is the custody property, asserted on the type
// rather than only on a response body: the served view has no field that could
// hold key material, so no future handler can leak one by accident.
func TestEABCredentialsCarryNoSecret(t *testing.T) {
	s := New(nil, Validators{})
	s.eabCredentials = map[string]*eabCredential{
		"b": {keyID: "b"},
		"a": {keyID: "a", policy: EABPolicy{AllowedIdentifiers: []string{"*.example.test"}, MaxOrders: 3}},
	}
	got := s.EABCredentials()
	if len(got) != 2 || got[0].KeyID != "a" || got[1].KeyID != "b" {
		t.Fatalf("EABCredentials is not sorted by key id: %+v", got)
	}
	if got[0].MaxOrders != 3 || len(got[0].AllowedIdentifiers) != 1 {
		t.Fatalf("scope did not survive into the served view: %+v", got[0])
	}
}

// TestAuthorizeOrderAgainstEABFailsClosedOnAMissingCredential covers the case a
// config reload creates: an account outlives the credential that admitted it.
// Treating that as unscoped would turn removing a credential into widening it.
func TestAuthorizeOrderAgainstEABFailsClosedOnAMissingCredential(t *testing.T) {
	s := New(nil, Validators{})
	s.eabCredentials = map[string]*eabCredential{}

	cred, reason := s.authorizeOrderAgainstEAB(&account{url: "u", eabKeyID: "gone"}, OrderRequest{})
	if cred != nil || reason == "" {
		t.Fatalf("a missing credential must fail closed, got cred=%v reason=%q", cred, reason)
	}

	// An account created without EAB is not constrained here: whether the
	// deployment requires EAB at all is decided at newAccount, not re-litigated
	// on every order.
	if _, reason := s.authorizeOrderAgainstEAB(&account{url: "u"}, OrderRequest{}); reason != "" {
		t.Errorf("an account with no EAB must not be denied here, got %q", reason)
	}
	if _, reason := s.authorizeOrderAgainstEAB(nil, OrderRequest{}); reason != "" {
		t.Errorf("a nil account must not produce a denial reason, got %q", reason)
	}
}
