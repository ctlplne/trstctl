// SPDX-License-Identifier: BUSL-1.1

package relay

import (
	"context"
	"testing"

	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/discovery/netscan"
)

// Part 4: the relay forwards what its scanner observed on the served chain,
// as hashes and check codes, beside the leaf's metadata.
func TestRelayScanSinkCarriesTheKeyObservation(t *testing.T) {
	var sink relayScanSink
	keys := netscan.KeyObservation{SPKISHA256: "aa", AuthorityKeyID: "bb", ChainSPKISHA256: []string{"cc"}, ChainCertSHA256: []string{"dd"}, WeakKeyChecks: []string{"key_size"}}
	if err := sink.Record(context.Background(), netscan.Found{Address: "10.0.0.1:443", Cert: certinfo.Info{SHA256Fingerprint: "ee", Subject: "CN=x"}, Keys: keys}); err != nil {
		t.Fatal(err)
	}
	f := sink.findings[0]
	if f.SPKISHA256 != "aa" || f.AuthorityKeyID != "bb" || f.ChainSPKISHA256[0] != "cc" || f.ChainCertSHA256[0] != "dd" || f.WeakKeyChecks[0] != "key_size" || f.Fingerprint != "ee" {
		t.Fatalf("finding = %+v", f)
	}
}
