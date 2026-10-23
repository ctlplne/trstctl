// SPDX-License-Identifier: BUSL-1.1

package trust

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"
)

// Every shipped entry carries its certificate's subject key identifier, so a
// leaf issued under one of the eight intermediates is found from its own
// authority key identifier.
func TestShippedEntriesCarrySubjectKeyIDs(t *testing.T) {
	list := Shipped()
	for _, e := range list.Entries() {
		if !isKeyIDHex(e.SubjectKeyID) {
			t.Fatalf("shipped entry %q has no subject key id", e.Name)
		}
	}
	for _, form := range []string{"34eaea0cebc90adaf9d0c5e2ed9b78c9879e1b6c", "34:EA:EA:0C:EB:C9:0A:DA:F9:D0:C5:E2:ED:9B:78:C9:87:9E:1B:6C"} {
		if e, ok := list.MatchIssuerKeyID(form); !ok || e.Name != "EM OV TLS CA - G3C" {
			t.Fatalf("issuer key id %s = %+v %v, want EM OV TLS CA - G3C", form, e, ok)
		}
	}
	if _, ok := list.MatchIssuerKeyID(""); ok {
		t.Fatal("an empty authority key identifier matched an entry")
	}
	for _, bad := range []string{"abc", "zz", strings.Repeat("ab", 65)} {
		data := `{"schema":1,"updated":"2026-10-23","notes":"","entries":[{"name":"x","kind":"root","spki_sha256":"` + strings.Repeat("ab", 32) + `","subject_key_id":"` + bad + `","reason":"r","sources":["s"],"since":"2026-10-23"}]}`
		if _, err := Parse([]byte(data)); err == nil {
			t.Fatalf("subject_key_id %q parsed", bad)
		}
	}
}

func emOVTLSG3C(t *testing.T) *x509.Certificate {
	t.Helper()
	data, err := os.ReadFile("testdata/em-ov-tls-ca-g3c.pem")
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatal("no PEM block in the fixture")
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// ExposureOf finds the certificate itself, an issuer in its recorded chain,
// or an issuer named only by its authority key identifier; a clean
// certificate has no exposure.
func TestExposureOfFindsTheCertificateItsChainOrItsIssuer(t *testing.T) {
	list := Shipped()
	inter := emOVTLSG3C(t)
	if x, ok, err := list.ExposureOf(inter.Raw, nil); err != nil || !ok || x.How != ExposedItself || x.Entry.Name != "EM OV TLS CA - G3C" {
		t.Fatalf("the intermediate itself: %+v %v %v", x, ok, err)
	}
	// A leaf issued by a CA certificate that carries the intermediate's subject
	// key identifier, i.e. a leaf whose authority key identifier names it.
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(10), Subject: pkix.Name{CommonName: "EM OV TLS CA - G3C"}, SubjectKeyId: inter.SubjectKeyId, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTmpl := &x509.Certificate{SerialNumber: big.NewInt(11), Subject: pkix.Name{CommonName: "shop.example.test"}, DNSNames: []string{"shop.example.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(mustParse(t, leafDER).AuthorityKeyId); got != hex.EncodeToString(inter.SubjectKeyId) {
		t.Fatalf("leaf authority key id %s", got)
	}
	if x, ok, err := list.ExposureOf(leafDER, nil); err != nil || !ok || x.How != ExposedIssuer || x.Entry.Name != "EM OV TLS CA - G3C" {
		t.Fatalf("leaf by issuer key id: %+v %v %v", x, ok, err)
	}
	// With the real intermediate recorded in its chain, the chain match wins.
	if x, ok, err := list.ExposureOf(leafDER, [][]byte{inter.Raw}); err != nil || !ok || x.How != ExposedChain || !strings.Contains(x.Subject, "EM OV TLS CA - G3C") {
		t.Fatalf("leaf with its chain: %+v %v %v", x, ok, err)
	}
	clean := newTestCA(t, "Clean Root", "clean.example.test")
	cleanLeaf, _ := pem.Decode(clean.leafPEM)
	if _, ok, err := list.ExposureOf(cleanLeaf.Bytes, [][]byte{clean.interDER, clean.rootDER}); err != nil || ok {
		t.Fatalf("a clean chain is exposed: %v %v", ok, err)
	}
	if _, _, err := list.ExposureOf([]byte("not a certificate"), nil); err == nil {
		t.Fatal("garbage parsed as a certificate")
	}
}

func mustParse(t *testing.T, der []byte) *x509.Certificate {
	t.Helper()
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestMatchNameIsExactOnTheEntryName(t *testing.T) {
	list := Shipped()
	if e, ok := list.MatchName("EM OV TLS CA - G3C"); !ok || e.Kind != KindIntermediate {
		t.Fatalf("exact name: %+v %v", e, ok)
	}
	for _, name := range []string{"", "em ov tls ca - g3c", "EM OV TLS CA", "Some Other CA"} {
		if _, ok := list.MatchName(name); ok {
			t.Fatalf("name %q matched", name)
		}
	}
}
