// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"testing"

	"trstctl.com/trstctl/internal/crypto/certinfo"
)

// A migration member's predecessor may carry DNS names, IP addresses or both;
// identifiers the host CSR path cannot express stay refused (A35).
func TestMigrationMemberSubjectAdmitsDNSAndIPPredecessors(t *testing.T) {
	t.Parallel()
	cn, dns, ips, err := migrationMemberSubject(certinfo.Info{
		CommonName: "api.example.test", DNSNames: []string{"api.example.test", "www.example.test"},
		IPAddresses: []string{"10.0.0.7", "10.0.0.7", "2001:db8:0:0::1"},
	})
	if err != nil || cn != "api.example.test" || len(dns) != 2 || len(ips) != 2 || ips[1] != "2001:db8::1" {
		t.Fatalf("dns+ip = %q %v %v %v; want both sets, de-duplicated and normalized", cn, dns, ips, err)
	}
	cn, dns, ips, err = migrationMemberSubject(certinfo.Info{CommonName: "10.0.0.7", IPAddresses: []string{"10.0.0.7"}})
	if err != nil || cn != "10.0.0.7" || len(dns) != 0 || len(ips) != 1 {
		t.Fatalf("ip-only = %q %v %v %v; want the address as the subject", cn, dns, ips, err)
	}
	for name, info := range map[string]certinfo.Info{
		"email": {DNSNames: []string{"api.example.test"}, EmailAddresses: []string{"ops@example.test"}},
		"uri":   {DNSNames: []string{"api.example.test"}, URIs: []string{"spiffe://example.test/api"}},
		"none":  {CommonName: "api.example.test"},
	} {
		if _, _, _, err := migrationMemberSubject(info); err == nil {
			t.Errorf("%s predecessor was admitted; the host CSR path cannot preserve it", name)
		}
	}
}
