// SPDX-License-Identifier: BUSL-1.1

package trust

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

// twoPathPKI is a server leaf under an intermediate key that carries two
// certificates: one issued by a root the test may distrust and a cross-sign
// issued by a clean root. The eMudhra shape: every intermediate had an emSign
// issuance and an AAA Certificate Services cross-sign.
type twoPathPKI struct {
	rootD, rootC   *x509.Certificate
	rootDKey       *ecdsa.PrivateKey
	interD, interC []byte
	interCert      *x509.Certificate
	leaf           []byte
	leafKey        *ecdsa.PrivateKey
}

func newTwoPathPKI(t *testing.T) twoPathPKI {
	t.Helper()
	key := func() *ecdsa.PrivateKey {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	now := time.Now()
	ca := func(serial int64, cn string, parent *x509.Certificate, pub *ecdsa.PublicKey, signer *ecdsa.PrivateKey) (*x509.Certificate, []byte) {
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: cn}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
		if parent == nil {
			parent = tmpl
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
		if err != nil {
			t.Fatal(err)
		}
		c, _ := x509.ParseCertificate(der)
		return c, der
	}
	dKey, cKey, iKey, lKey := key(), key(), key(), key()
	rootD, _ := ca(1, "Distrusted Root", nil, &dKey.PublicKey, dKey)
	rootC, _ := ca(2, "Clean Root", nil, &cKey.PublicKey, cKey)
	interCert, interD := ca(3, "Intermediate", rootD, &iKey.PublicKey, dKey)
	_, interC := ca(4, "Intermediate", rootC, &iKey.PublicKey, cKey)
	leafTmpl := &x509.Certificate{SerialNumber: big.NewInt(5), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leaf, err := x509.CreateCertificate(rand.Reader, leafTmpl, interCert, &lKey.PublicKey, iKey)
	if err != nil {
		t.Fatal(err)
	}
	return twoPathPKI{rootD: rootD, rootC: rootC, rootDKey: dKey, interD: interD, interC: interC, interCert: interCert, leaf: leaf, leafKey: lKey}
}

func serve(t *testing.T, chain [][]byte, key *ecdsa.PrivateKey) string {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{{Certificate: chain, PrivateKey: key}}, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _ = c.(*tls.Conn).Handshake(); time.Sleep(50 * time.Millisecond); _ = c.Close() }()
		}
	}()
	return net.JoinHostPort("localhost", portOf(ln.Addr()))
}

func dialWith(t *testing.T, addr string, cfg *tls.Config) (*tls.Conn, error) {
	t.Helper()
	d := &tls.Dialer{NetDialer: &net.Dialer{Timeout: 5 * time.Second}, Config: cfg}
	conn, err := d.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	return conn.(*tls.Conn), nil
}

func entryFor(c *x509.Certificate, name string) Entry {
	return Entry{Name: name, Kind: KindIntermediate, SPKISHA256: SPKISHA256(c), Reason: "test incident", Sources: []string{"test"}, Since: "2026-10-23"}
}

// A99 of the eMudhra plan: the check accepts a server with a clean path beside
// a distrusted one, refuses a server whose only paths run through a distrusted
// root, a distrusted intermediate, or another certificate for a distrusted key,
// names the entry, and holds on resumed sessions.
func TestVerifyConnectionAcceptsOneCleanPathAndNamesTheEntryOtherwise(t *testing.T) {
	pki := newTwoPathPKI(t)
	both := x509.NewCertPool()
	both.AddCert(pki.rootD)
	both.AddCert(pki.rootC)
	addr := serve(t, [][]byte{pki.leaf, pki.interD, pki.interC}, pki.leafKey)

	rootDEntry := Entry{Name: "Distrusted Root", Kind: KindRoot, SPKISHA256: SPKISHA256(pki.rootD), CertSHA256: CertSHA256(pki.rootD), Reason: "removed", Sources: []string{"test"}, Since: "2026-10-23"}
	cfg := &tls.Config{RootCAs: both, ServerName: "localhost", MinVersion: tls.VersionTLS12, VerifyConnection: VerifyConnection(listWith(t, rootDEntry))}
	conn, err := dialWith(t, addr, cfg)
	if err != nil {
		t.Fatalf("a server with a clean path beside the distrusted root was refused: %v", err)
	}
	_ = conn.Close()

	// Only the distrusted path: the entry is named.
	onlyD := x509.NewCertPool()
	onlyD.AddCert(pki.rootD)
	cfg = &tls.Config{RootCAs: onlyD, ServerName: "localhost", MinVersion: tls.VersionTLS12, VerifyConnection: VerifyConnection(listWith(t, rootDEntry))}
	if _, err := dialWith(t, addr, cfg); err == nil || !strings.Contains(err.Error(), `"Distrusted Root"`) {
		t.Fatalf("only-distrusted-root handshake = %v, want a refusal naming the entry", err)
	}

	// The intermediate KEY distrusted: both its certificates are caught, the
	// clean root does not help, and the error names the entry.
	keyList := listWith(t, entryFor(pki.interCert, "Weak Intermediate Key"))
	cfg = &tls.Config{RootCAs: both, ServerName: "localhost", MinVersion: tls.VersionTLS12, VerifyConnection: VerifyConnection(keyList)}
	_, err = dialWith(t, addr, cfg)
	var de *DistrustError
	if err == nil || !errors.As(err, &de) || de.Entry.Name != "Weak Intermediate Key" {
		t.Fatalf("distrusted intermediate key handshake = %v", err)
	}

	// Verification off (the loopback development client): the presented
	// certificates are still checked.
	cfg = &tls.Config{InsecureSkipVerify: true, ServerName: "localhost", MinVersion: tls.VersionTLS12, VerifyConnection: VerifyConnection(keyList)} // #nosec G402 -- the test proves the check runs with verification off (CWE-295)
	if _, err := dialWith(t, addr, cfg); err == nil || !strings.Contains(err.Error(), "Weak Intermediate Key") {
		t.Fatalf("verification-off handshake = %v, want the entry named from PeerCertificates", err)
	}

	// Resumption: the second connection resumes the first session and is still
	// refused once the key is distrusted (the check runs on resumed sessions).
	cache := tls.NewLRUClientSessionCache(4)
	resumable := func(list *List) *tls.Config {
		return &tls.Config{RootCAs: both, ServerName: "localhost", MinVersion: tls.VersionTLS13, ClientSessionCache: cache, VerifyConnection: VerifyConnection(list)}
	}
	first, err := dialWith(t, addr, resumable(listWith(t, rootDEntry)))
	if err != nil {
		t.Fatalf("first resumable handshake: %v", err)
	}
	// Read until the server closes so the session ticket arrives.
	_ = first.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, _ = first.Read(make([]byte, 1))
	_ = first.Close()
	second, err := dialWith(t, addr, resumable(listWith(t, rootDEntry)))
	if err != nil {
		t.Fatalf("second (resumed) handshake with a clean path: %v", err)
	}
	resumed := second.ConnectionState().DidResume
	_ = second.Close()
	if !resumed {
		t.Log("session was not resumed; the resumption branch is not exercised on this platform")
	}
	if _, err := dialWith(t, addr, resumable(keyList)); err == nil || !strings.Contains(err.Error(), "Weak Intermediate Key") {
		t.Fatalf("resumed handshake under a distrusted key = %v, want refusal", err)
	}
}

func TestHardenTLSConfigChainsAndActiveListAddsOperatorEntries(t *testing.T) {
	pki := newTwoPathPKI(t)
	onlyD := x509.NewCertPool()
	onlyD.AddCert(pki.rootD)
	addr := serve(t, [][]byte{pki.leaf, pki.interD}, pki.leafKey)
	t.Cleanup(func() { _ = SetOperator(nil) })

	calls := 0
	cfg := HardenTLSConfig(&tls.Config{RootCAs: onlyD, ServerName: "localhost", MinVersion: tls.VersionTLS12, VerifyConnection: func(tls.ConnectionState) error { calls++; return nil }})
	conn, err := dialWith(t, addr, cfg)
	if err != nil || calls != 1 {
		t.Fatalf("hardened config with the shipped list only = %v (prior check calls %d)", err, calls)
	}
	_ = conn.Close()

	// An operator addition in configuration takes effect on the same config.
	if err := SetOperator(listWith(t, Entry{Name: "Operator-distrusted Root", Kind: KindRoot, SPKISHA256: SPKISHA256(pki.rootD), Reason: "air-gapped site cannot take a release", Sources: []string{"ticket"}, Since: "2026-10-23"})); err != nil {
		t.Fatal(err)
	}
	if _, err := dialWith(t, addr, cfg); err == nil || !strings.Contains(err.Error(), "Operator-distrusted Root") {
		t.Fatalf("operator entry not applied: %v", err)
	}
	if Active().Len() != Shipped().Len()+1 {
		t.Fatalf("active list = %d entries", Active().Len())
	}
	if err := SetOperator(nil); err != nil {
		t.Fatal(err)
	}
	if Active().Len() != Shipped().Len() {
		t.Fatal("resetting the operator list did not restore the shipped list")
	}
	if HardenTransport(nil) != nil {
		t.Fatal("HardenTransport(nil) must stay nil")
	}
}
