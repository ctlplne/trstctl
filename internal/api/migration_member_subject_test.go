// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"testing"

	"trstctl.com/trstctl/internal/crypto/certinfo"
)

// A migration member's predecessor may carry DNS names, IP addresses,
// rfc822Names and URIs in any mix; each half is frozen exactly (A35, extended).
func TestMigrationMemberSubjectAdmitsDNSAndIPPredecessors(t *testing.T) {
	t.Parallel()
	cn, dns, ips, _, _, err := migrationMemberSubject(certinfo.Info{
		CommonName: "api.example.test", DNSNames: []string{"api.example.test", "www.example.test"},
		IPAddresses: []string{"10.0.0.7", "10.0.0.7", "2001:db8:0:0::1"},
	})
	if err != nil || cn != "api.example.test" || len(dns) != 2 || len(ips) != 2 || ips[1] != "2001:db8::1" {
		t.Fatalf("dns+ip = %q %v %v %v; want both sets, de-duplicated and normalized", cn, dns, ips, err)
	}
	cn, dns, ips, _, _, err = migrationMemberSubject(certinfo.Info{CommonName: "10.0.0.7", IPAddresses: []string{"10.0.0.7"}})
	if err != nil || cn != "10.0.0.7" || len(dns) != 0 || len(ips) != 1 {
		t.Fatalf("ip-only = %q %v %v %v; want the address as the subject", cn, dns, ips, err)
	}
	// A35 extension: rfc822Names and URIs are carried exactly, on their own halves.
	cn, dns, ips, emails, uris, err := migrationMemberSubject(certinfo.Info{
		DNSNames: []string{"api.example.test"}, EmailAddresses: []string{"Ops@example.test", "ops@example.test"},
		URIs: []string{"spiffe://example.test/api", "spiffe://example.test/api"},
	})
	if err != nil || cn != "api.example.test" || len(dns) != 1 || len(ips) != 0 || len(emails) != 1 || emails[0] != "Ops@example.test" || len(uris) != 1 {
		t.Fatalf("dns+email+uri = %q %v %v %v %v %v; want every half kept, de-duplicated", cn, dns, ips, emails, uris, err)
	}
	if cn, _, _, _, _, err := migrationMemberSubject(certinfo.Info{EmailAddresses: []string{"ops@example.test"}}); err != nil || cn != "ops@example.test" {
		t.Fatalf("email-only = %q %v; want the email as the subject", cn, err)
	}
	if _, _, _, _, _, err := migrationMemberSubject(certinfo.Info{CommonName: "api.example.test"}); err == nil {
		t.Error("a predecessor with no identifier at all was admitted")
	}
}
