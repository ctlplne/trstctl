// SPDX-License-Identifier: BUSL-1.1

package tlssource_test

import (
	"context"
	"encoding/pem"
	"os"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/cbom"
	"trstctl.com/trstctl/internal/cbom/tlssource"
	"trstctl.com/trstctl/internal/crypto/tlsprobe"
)

func fixtureDER(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile("../../keyposture/testdata/" + name) // #nosec G304 -- a fixed test fixture, named by the test itself (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(data)
	return block.Bytes
}

// Part 4: a CBOM certificate-key asset served beside one of the eight eMudhra
// intermediates is rated weak and out of policy, naming the entry; an
// ordinary served key keeps its plain rating.
func TestScanRatesTheServedChain(t *testing.T) {
	leaf, inter := fixtureDER(t, "leaf-under-em-ov-tls-ca-g3c.pem"), fixtureDER(t, "em-ov-tls-ca-g3c.pem")
	prober := func(context.Context, string) (tlsprobe.Result, error) {
		return tlsprobe.Result{TLSVersion: 0x0304, PeerCertificates: [][]byte{leaf, inter}}, nil
	}
	findings, err := tlssource.New([]string{"shop.example.test:443"}, tlssource.WithProber(prober)).Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var key cbom.Finding
	for _, f := range findings {
		if f.Kind == cbom.AssetCertKey {
			key = f
		}
	}
	c := cbom.Classify(key, cbom.DefaultPolicy())
	if c.Strength != cbom.StrengthWeak || !c.OutOfPolicy || !strings.Contains(strings.Join(c.Reasons, "|"), "EM OV TLS CA - G3C") {
		t.Fatalf("served under EM OV TLS CA - G3C: %+v (finding %+v)", c, key)
	}
	ordinary := fixtureDER(t, "ecdsa-p256-ordinary.pem")
	plain := func(context.Context, string) (tlsprobe.Result, error) {
		return tlsprobe.Result{TLSVersion: 0x0304, PeerCertificates: [][]byte{ordinary}}, nil
	}
	findings, err = tlssource.New([]string{"api.example.test:443"}, tlssource.WithProber(plain)).Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		if f.Kind == cbom.AssetCertKey {
			if c := cbom.Classify(f, cbom.DefaultPolicy()); c.Strength == cbom.StrengthWeak {
				t.Fatalf("an ordinary served key was rated weak: %+v", c)
			}
		}
	}
}
