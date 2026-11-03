// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
)

// P15 part c: a stock S/MIME client names the mailbox as the CSR's common name;
// profile vetting must not take it for a DNS name.
func TestProtocolDNSNamesNeverTakesAMailboxCommonNameP15(t *testing.T) {
	for name, tc := range map[string]struct {
		info crypto.CSRInfo
		want string
	}{
		"mailbox common name":           {crypto.CSRInfo{CommonName: "alice@p15.test", EmailAddresses: []string{"alice@p15.test"}}, ""},
		"legacy host common name":       {crypto.CSRInfo{CommonName: "www.example.test"}, "www.example.test"},
		"DNS SANs over the common name": {crypto.CSRInfo{CommonName: "x.example.test", DNSNames: []string{"a.example.test", "b.example.test"}}, "a.example.test,b.example.test"},
		"nothing":                       {crypto.CSRInfo{}, ""},
	} {
		if got := strings.Join(protocolDNSNames(tc.info), ","); got != tc.want {
			t.Errorf("%s: DNS names = %q, want %q", name, got, tc.want)
		}
	}
}
