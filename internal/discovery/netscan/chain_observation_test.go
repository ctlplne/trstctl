// SPDX-License-Identifier: BUSL-1.1

package netscan_test

import (
	"context"
	"encoding/hex"
	"encoding/pem"
	"os"
	"testing"

	"trstctl.com/trstctl/internal/crypto/tlsprobe"
	"trstctl.com/trstctl/internal/discovery/netscan"
)

// Part 4: the default scanner observes the served chain, not only the leaf:
// the leaf's key hash and authority key identifier, each served issuer's key
// and certificate hashes, and the weak-key checks that fire. Here the leaf is
// issued under the real EM OV TLS CA - G3C's key identifier and that
// intermediate is served beside it.
func TestScanObservesTheServedChain(t *testing.T) {
	data, err := os.ReadFile("../../keyposture/testdata/em-ov-tls-ca-g3c.pem") // #nosec G304 -- a fixed test fixture, named by the test itself (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(data)
	ski, _ := hex.DecodeString("34eaea0cebc90adaf9d0c5e2ed9b78c9879e1b6c")
	srv, err := tlsprobe.NewServingTestServerUnder(ski, [][]byte{block.Bytes}, "shop.example.test")
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	sink := netscan.NewMemorySink()
	s := netscan.New(sink, netscan.WithAllowLoopbackTargets(true))
	defer s.Close()
	if rep := s.Scan(context.Background(), []string{srv.Addr}); rep.Discovered != 1 {
		t.Fatalf("report = %+v", rep)
	}
	found := sink.All()
	keys := found[0].Keys
	if keys.AuthorityKeyID != "34eaea0cebc90adaf9d0c5e2ed9b78c9879e1b6c" || keys.SPKISHA256 == "" || len(keys.ChainSPKISHA256) != 1 ||
		keys.ChainSPKISHA256[0] != "63ecefee431d49523bc1136c4e72d0206a477086caf606cd5cf025686c109cf8" || len(keys.ChainCertSHA256) != 1 || len(keys.WeakKeyChecks) != 0 {
		t.Fatalf("observation = %+v", keys)
	}
}
