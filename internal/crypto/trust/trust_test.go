// SPDX-License-Identifier: BUSL-1.1

package trust

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

// The shipped list is the eMudhra incident of October 2026: the three emSign
// roots Mozilla removed (matched by key and by certificate) and the eight
// intermediates whose P-384 private keys are small integers (matched by key,
// so both certificates for each key are covered).
func TestShippedListIsTheIncidentList(t *testing.T) {
	l := Shipped()
	if l.Len() != 11 {
		t.Fatalf("shipped entries = %d, want 11", l.Len())
	}
	roots, intermediates := 0, 0
	for _, e := range l.Entries() {
		switch e.Kind {
		case KindRoot:
			roots++
			if e.CertSHA256 == "" {
				t.Errorf("root %q has no cert_sha256", e.Name)
			}
		case KindIntermediate:
			intermediates++
			if !strings.Contains(e.Reason, "*G") {
				t.Errorf("intermediate %q does not name its recoverable scalar: %q", e.Name, e.Reason)
			}
		}
		if e.Origin != OriginShipped || len(e.Sources) == 0 || e.Since == "" {
			t.Errorf("entry %q = origin %q sources %d since %q", e.Name, e.Origin, len(e.Sources), e.Since)
		}
		if e.SPKISHA256 != strings.ToLower(e.SPKISHA256) {
			t.Errorf("entry %q hash is not lowercase", e.Name)
		}
	}
	if roots != 3 || intermediates != 8 {
		t.Fatalf("roots %d intermediates %d, want 3 and 8", roots, intermediates)
	}
	// The eight intermediate SPKIs are the ones Go 1.26.10 distrusts; a typo
	// here would silently narrow the list.
	for _, spki := range []string{
		"ebed6475c2c2d80fcb199f3fe8dd6e6b3ce60b77eb15d4e42c3dec0c6f5b5105", "49dd353dc2b919a3770645117d0e60c16115e7d1bc259eefe734b00ea434fe5f",
		"e0254c7fcdc265e2f0f8a428dabb75ab4ae039b4872d62f5ee57f0877d5a8a41", "5c0660a2b164910d8ff589c18e14552e9e0ec237dcefe2cb736d41a4811f81a0",
		"43bffa19d6ef651451f6841e019931e96f6f2eaeff28ab4b6f1ce4576de2717b", "63ecefee431d49523bc1136c4e72d0206a477086caf606cd5cf025686c109cf8",
		"ec4ffa1ad0ac88081314b7aaffef6a91f97cd57291bb5ba686c5415f5eb4f6b6", "92c063d67e8f14db71d288e11266ffdaf69cbf115f7bab14f3bc2f68d25e0e30",
	} {
		if e, ok := l.MatchHashes(spki, ""); !ok || e.Kind != KindIntermediate {
			t.Errorf("spki %s is not a shipped intermediate entry", spki[:12])
		}
	}
	if e, ok := l.MatchHashes("0000000000000000000000000000000000000000000000000000000000000000", "86a1ecba089c4a8d3bbe2734c612ba341d813e043cf9e8a862cd5c57a36bbe6b"); !ok || e.Name != "emSign ECC Root CA - G3" {
		t.Fatalf("certificate-hash match for the G3 root = %+v %v", e, ok)
	}
}

func TestParseRejectsMalformedLists(t *testing.T) {
	for name, body := range map[string]string{
		"bad hash":    `{"schema":1,"entries":[{"name":"x","kind":"root","spki_sha256":"abc","reason":"r","sources":["s"],"since":"2026-10-23"}]}`,
		"no reason":   `{"schema":1,"entries":[{"name":"x","kind":"root","spki_sha256":"` + strings.Repeat("a", 64) + `","reason":" ","sources":["s"],"since":"2026-10-23"}]}`,
		"no source":   `{"schema":1,"entries":[{"name":"x","kind":"root","spki_sha256":"` + strings.Repeat("a", 64) + `","reason":"r","sources":[],"since":"2026-10-23"}]}`,
		"bad kind":    `{"schema":1,"entries":[{"name":"x","kind":"leaf","spki_sha256":"` + strings.Repeat("a", 64) + `","reason":"r","sources":["s"],"since":"2026-10-23"}]}`,
		"duplicate":   `{"schema":1,"entries":[{"name":"x","kind":"root","spki_sha256":"` + strings.Repeat("a", 64) + `","reason":"r","sources":["s"],"since":"2026-10-23"},{"name":"y","kind":"root","spki_sha256":"` + strings.Repeat("A", 64) + `","reason":"r","sources":["s"],"since":"2026-10-23"}]}`,
		"schema":      `{"schema":2,"entries":[]}`,
		"unknown key": `{"schema":1,"entries":[],"extra":1}`,
	} {
		if _, err := Parse([]byte(body)); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
}

// testCA is a throwaway CA and leaf for one test.
type testCA struct {
	rootPEM, rootDER []byte
	rootCert         *x509.Certificate
	rootKey          *ecdsa.PrivateKey
	leafPEM          []byte
	leafKey          *ecdsa.PrivateKey
	interDER         []byte
}

func newTestCA(t *testing.T, cn string, host string) testCA {
	t.Helper()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	rootCert, _ := x509.ParseCertificate(rootDER)
	interKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	interTmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: cn + " Intermediate"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	interDER, err := x509.CreateCertificate(rand.Reader, interTmpl, rootCert, &interKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	interCert, _ := x509.ParseCertificate(interDER)
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTmpl := &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: host}, DNSNames: []string{host}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, interCert, &leafKey.PublicKey, interKey)
	if err != nil {
		t.Fatal(err)
	}
	return testCA{
		rootPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER}), rootDER: rootDER, rootCert: rootCert, rootKey: rootKey,
		leafPEM: append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: interDER})...),
		leafKey: leafKey, interDER: interDER,
	}
}

func listWith(t *testing.T, entries ...Entry) *List {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"schema": 1, "updated": "2026-10-23", "entries": entries})
	l, err := Parse(body)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func TestFilterBundleDropsDistrustedKeysAndIsDeterministic(t *testing.T) {
	bad := newTestCA(t, "Bad Root", "bad.example.test")
	good := newTestCA(t, "Good Root", "good.example.test")
	// A cross-sign for the bad key: a different certificate, same SPKI.
	cross := &x509.Certificate{SerialNumber: big.NewInt(9), Subject: pkix.Name{CommonName: "Bad Root cross-signed"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true}
	crossDER, err := x509.CreateCertificate(rand.Reader, cross, good.rootCert, bad.rootCert.PublicKey, good.rootKey)
	if err != nil {
		t.Fatal(err)
	}
	crossPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: crossDER})
	list := listWith(t, Entry{Name: "Bad Root", Kind: KindRoot, SPKISHA256: SPKISHA256(bad.rootCert), CertSHA256: CertSHA256(bad.rootCert), Reason: "test", Sources: []string{"test"}, Since: "2026-10-23"})

	bundle := bytes.Join([][]byte{[]byte("# a comment line a distro may add\n"), good.rootPEM, bad.rootPEM, crossPEM}, nil)
	first, err := FilterBundle(bundle, list)
	if err != nil {
		t.Fatal(err)
	}
	if first.Kept != 1 || len(first.Dropped) != 2 || first.Dropped[0].Entry != "Bad Root" || first.Dropped[1].Entry != "Bad Root" {
		t.Fatalf("filter = kept %d dropped %+v", first.Kept, first.Dropped)
	}
	if !bytes.Equal(first.Bundle, good.rootPEM) {
		t.Fatalf("kept bundle is not the good root's normalised PEM")
	}
	second, _ := FilterBundle(bundle, list)
	if !bytes.Equal(first.Bundle, second.Bundle) {
		t.Fatal("filter output differs between runs")
	}
	if _, err := FilterBundle([]byte("no certificates here"), list); err == nil {
		t.Fatal("an empty bundle filtered without error")
	}
	if _, err := FilterBundle(append(good.rootPEM, []byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n")...), list); err == nil {
		t.Fatal("a bundle with an unparseable certificate filtered without error")
	}
	if _, err := FilterBundle(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1}}), list); err == nil {
		t.Fatal("a non-certificate block filtered without error")
	}
}

func TestMergeOnlyAdds(t *testing.T) {
	shipped := Shipped()
	extra := listWith(t, Entry{Name: "Operator Root", Kind: KindRoot, SPKISHA256: strings.Repeat("ab", 32), Reason: "operator says so", Sources: []string{"ticket"}, Since: "2026-10-23"},
		Entry{Name: "EM DV TLS CA - G3B (operator copy)", Kind: KindIntermediate, SPKISHA256: "ebed6475c2c2d80fcb199f3fe8dd6e6b3ce60b77eb15d4e42c3dec0c6f5b5105", Reason: "duplicate of a shipped key", Sources: []string{"ticket"}, Since: "2026-10-23"})
	merged, err := shipped.Merge(extra)
	if err != nil {
		t.Fatal(err)
	}
	if merged.Len() != shipped.Len()+1 {
		t.Fatalf("merged = %d entries, want shipped+1 (a duplicate key keeps the shipped entry)", merged.Len())
	}
	if e, ok := merged.MatchHashes(strings.Repeat("ab", 32), ""); !ok || e.Origin != OriginOperator {
		t.Fatalf("operator entry = %+v %v", e, ok)
	}
	if e, _ := merged.MatchHashes("ebed6475c2c2d80fcb199f3fe8dd6e6b3ce60b77eb15d4e42c3dec0c6f5b5105", ""); e.Origin != OriginShipped {
		t.Fatalf("shipped entry was replaced by the operator copy: %+v", e)
	}
}

func TestProbeNamesADistrustedChainAndAcceptsACleanOne(t *testing.T) {
	ca := newTestCA(t, "Probe Root", "localhost")
	cert, err := tls.X509KeyPair(ca.leafPEM, pemKey(t, ca.leafKey))
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _ = c.(*tls.Conn).Handshake(); _ = c.Close() }()
		}
	}()
	roots := x509.NewCertPool()
	roots.AddCert(ca.rootCert)
	addr := net.JoinHostPort("localhost", portOf(ln.Addr()))

	clean := Probe(context.Background(), addr, Shipped(), roots, 5*time.Second)
	if !clean.OK || clean.Root != "CN=Probe Root" || len(clean.Chain) != 3 {
		t.Fatalf("clean probe = %+v", clean)
	}
	inter, _ := x509.ParseCertificate(ca.interDER)
	tainted := listWith(t, Entry{Name: "Probe Intermediate", Kind: KindIntermediate, SPKISHA256: SPKISHA256(inter), Reason: "test", Sources: []string{"test"}, Since: "2026-10-23"})
	bad := Probe(context.Background(), addr, tainted, roots, 5*time.Second)
	if bad.OK || bad.Distrusted != "Probe Intermediate" || !strings.Contains(bad.Error, "Probe Intermediate") {
		t.Fatalf("tainted probe = %+v", bad)
	}
	unreachable := Probe(context.Background(), "127.0.0.1:1", Shipped(), roots, time.Second)
	if unreachable.OK || unreachable.Error == "" {
		t.Fatalf("unreachable probe = %+v", unreachable)
	}
}

func portOf(a net.Addr) string {
	_, p, _ := net.SplitHostPort(a.String())
	return p
}

func pemKey(t *testing.T, k *ecdsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
}

func TestBundleFromAPKReadsTheDataStream(t *testing.T) {
	// Three gzip members like a real apk: a signature, the control archive,
	// then the data archive carrying the bundle.
	want := []byte("-----BEGIN CERTIFICATE-----\nMA==\n-----END CERTIFICATE-----\n")
	apk := bytes.Join([][]byte{gzTar(t, ".SIGN.RSA.x", []byte("sig")), gzTar(t, ".PKGINFO", []byte("pkgname = ca-certificates-bundle")), gzTar(t, "etc/ssl/certs/ca-certificates.crt", want)}, nil)
	got, err := BundleFromAPK(apk)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("BundleFromAPK = %q %v", got, err)
	}
	if _, err := BundleFromAPK(bytes.Join([][]byte{gzTar(t, ".SIGN", []byte("x")), gzTar(t, ".PKGINFO", []byte("y"))}, nil)); err == nil {
		t.Fatal("an apk without the bundle extracted without error")
	}
}
