// SPDX-License-Identifier: BUSL-1.1

package acme

import (
	"bytes"
	"testing"
)

// P15-L3: an EAB credential's allowed identifiers may scope mailboxes: a
// domain, a domain and those under it, or one mailbox. A mail entry never
// admits a DNS name and a DNS entry never a mailbox; a malformed mail entry
// is refused when a credential is installed.
func TestEABCredentialsScopeMailDomainsP15L3(t *testing.T) {
	policy := EABPolicy{AllowedIdentifiers: []string{"@p15l3.test", "@*.corp.p15l3.test", "bob@other.test", "*.hosts.p15l3.test"}}
	for identifier, want := range map[string]bool{
		"alice@p15l3.test":         true,
		"Alice@P15L3.TEST":         true,
		"carol@corp.p15l3.test":    true,
		"carol@eu.corp.p15l3.test": true,
		"bob@other.test":           true,
		"eve@other.test":           false,
		"alice@evilp15l3.test":     false,
		"alice@sub.p15l3.test":     false,
		"web.hosts.p15l3.test":     true,
		"web@hosts.p15l3.test":     false,
		"p15l3.test":               false,
		"corp.p15l3.test":          false,
	} {
		if got := policy.permits(identifier); got != want {
			t.Fatalf("permits(%q) = %v, want %v", identifier, got, want)
		}
	}
	mailOnly := EABPolicy{AllowedIdentifiers: []string{"@p15l3.test"}}
	if mailOnly.permits("www.p15l3.test") {
		t.Fatal("a credential scoped to mailboxes admitted a DNS name")
	}
	if !(EABPolicy{}).permits("anyone@anywhere.test") {
		t.Fatal("an unscoped credential refused a mailbox")
	}
	for _, entry := range []string{"@", "@*.", "@not a domain", "a@b@c.test", "*@p15l3.test", "@*.*.p15l3.test", " "} {
		if ValidEABIdentifierEntry(entry) == nil {
			t.Fatalf("entry %q was accepted", entry)
		}
	}
	for _, entry := range []string{"@p15l3.test", "@*.corp.p15l3.test", "bob@other.test", "*.hosts.p15l3.test", "api.p15l3.test"} {
		if err := ValidEABIdentifierEntry(entry); err != nil {
			t.Fatalf("entry %q: %v", entry, err)
		}
	}
	srv := New(nil, AcceptAll{})
	if _, err := srv.WithExternalAccountBindings(true, []ExternalAccountBindingKey{{KeyID: "mail",
		HMACKey: bytes.Repeat([]byte{0x15}, 32), Policy: EABPolicy{AllowedIdentifiers: []string{"@not a domain"}}}}); err == nil {
		t.Fatal("a credential with a malformed mail entry was installed")
	}
}
