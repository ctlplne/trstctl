// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"crypto/rand"
	"crypto/x509"
	"math/big"
	"net/url"
	"testing"
	"time"
)

func TestSPIFFEIDFromCertRequiresOneCanonicalIdentity(t *testing.T) {
	key, err := GenerateLockedKey(ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer key.Destroy()
	caDER, err := SelfSignedCACert(key, "SPIFFE extraction test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := newX509Signer(key)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		ids  []string
		want string
	}{
		{"valid", []string{"spiffe://served.test/ns/qa/sa/web"}, "spiffe://served.test/ns/qa/sa/web"},
		{"absent", nil, ""},
		{"wrong scheme", []string{"https://served.test/ns/qa"}, ""},
		{"two identities", []string{"spiffe://served.test/a", "spiffe://served.test/b"}, ""},
		{"duplicate identity", []string{"spiffe://served.test/a", "spiffe://served.test/a"}, ""},
		{"extra non-SPIFFE URI", []string{"https://served.test/a", "spiffe://served.test/a"}, ""},
		{"encoded path", []string{"spiffe://served.test/ns%2Fqa"}, ""},
		{"authority port", []string{"spiffe://served.test:443/a"}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			uris := []*url.URL{}
			for _, raw := range tc.ids {
				u, err := url.Parse(raw)
				if err != nil {
					t.Fatal(err)
				}
				uris = append(uris, u)
			}
			leaf := &x509.Certificate{SerialNumber: big.NewInt(2), URIs: uris, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
			der, err := x509.CreateCertificate(rand.Reader, leaf, ca, signer.Public(), signer)
			if err != nil {
				t.Fatal(err)
			}
			got, err := SPIFFEIDFromCert(der)
			if tc.want == "" {
				if err == nil || got != "" {
					t.Fatal("ambiguous or invalid signed identity was accepted")
				}
			} else if err != nil || got != tc.want {
				t.Fatalf("valid identity rejected: %v", err)
			}
		})
	}
}
