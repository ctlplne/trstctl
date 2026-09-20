// SPDX-License-Identifier: BUSL-1.1

package mtls

import (
	"bytes"
	"context"
	stdcrypto "crypto"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	boundary "trstctl.com/trstctl/internal/crypto"
)

func renewingTestAuthority(t *testing.T) (*boundary.LockedSigner, []byte, []byte) {
	t.Helper()
	key, err := boundary.GenerateLockedKey(boundary.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Destroy)
	der, err := boundary.SelfSignedCACert(key, "renewing server test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return key, der, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestRenewingServerCertificateRetainsTrustAcrossOutageAndExpiry(t *testing.T) {
	key, der, ca := renewingTestAuthority(t)
	var outage atomic.Bool
	var calls atomic.Int32
	source, err := NewRenewingServerCertificate(ca, []string{"localhost"}, func(csr []byte) ([]byte, error) {
		calls.Add(1)
		if outage.Load() {
			return nil, errors.New("test signer unavailable")
		}
		return boundary.SignServerCertFromCSR(der, key, csr, []string{"localhost"}, 6*time.Second)
	})
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	first := source.current.Load()
	clientID, err := GenerateAgentKey("renewing-client")
	if err != nil {
		t.Fatal(err)
	}
	defer clientID.Destroy()
	csr, err := clientID.CSR()
	if err != nil {
		t.Fatal(err)
	}
	chain, err := boundary.SignAgentClientCSR(der, key, csr, "spiffe://trstctl.example/tenant/test/agent/renewing-client", nil, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := clientID.UseCertificate(chain); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { defer close(done); source.Run(ctx, nil) }()
	t.Cleanup(func() { cancel(); <-done })
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("verified application")) }))
	srv.TLS = source.TLSConfig()
	srv.StartTLS()
	defer srv.Close()
	fetch := func(serverName string, identity ClientCertSource) (string, error) {
		tr, err := AgentHTTPTransport(identity, ca, serverName, nil)
		if err != nil {
			return "", err
		}
		defer tr.CloseIdleConnections()
		resp, err := (&http.Client{Transport: tr, Timeout: time.Second}).Get(srv.URL)
		if err != nil {
			return "", err
		}
		defer func() { _ = resp.Body.Close() }()
		body, err := io.ReadAll(resp.Body)
		return string(body), err
	}
	if body, err := fetch("localhost", clientID); err != nil || body != "verified application" {
		t.Fatalf("initial application: %s %v", body, err)
	}
	outage.Store(true)
	// The last good leaf stays usable while a bounded issuer retry is failing.
	deadline := time.Now().Add(5 * time.Second)
	for calls.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if calls.Load() < 2 {
		t.Fatal("renewal did not run before expiry")
	}
	if body, err := fetch("localhost", clientID); err != nil || body != "verified application" {
		t.Fatalf("valid old leaf during outage: %s %v", body, err)
	}
	if source.current.Load() != first {
		t.Fatal("failed renewal changed the current leaf")
	}
	if _, err := fetch("wrong.example", clientID); err == nil {
		t.Fatal("wrong hostname accepted during outage")
	}
	if _, err := fetch("localhost", nil); err == nil {
		t.Fatal("missing client certificate accepted during outage")
	}
	time.Sleep(time.Until(first.Leaf.NotAfter) + 100*time.Millisecond)
	if _, err := fetch("localhost", clientID); err == nil {
		t.Fatal("expired server leaf accepted")
	}
	outage.Store(false)
	deadline = time.Now().Add(3 * time.Second)
	for source.current.Load() == first && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if source.current.Load() == first {
		t.Fatal("issuer recovery did not replace expired leaf")
	}
	if !bytes.Equal(source.current.Load().Leaf.RawSubjectPublicKeyInfo, first.Leaf.RawSubjectPublicKeyInfo) {
		t.Fatal("certificate renewal changed the transport key")
	}
	if body, err := fetch("localhost", clientID); err != nil || body != "verified application" {
		t.Fatalf("recovered application: %s %v", body, err)
	}
	cancel()
	<-done
	source.Close()
	if _, err := fetch("localhost", clientID); err == nil {
		t.Fatal("closed identity still served")
	}
	if _, err := source.signer.Sign(nil, make([]byte, 32), stdcrypto.SHA256); err == nil {
		t.Fatal("destroyed locked key still signed")
	}
}

func TestRenewingServerCertificateRejectsInvalidReplacement(t *testing.T) {
	key, der, ca := renewingTestAuthority(t)
	otherKey, otherDER, _ := renewingTestAuthority(t)
	for _, kind := range []string{"malformed", "prefix", "suffix", "private", "empty", "wrong-ca", "wrong-host", "wrong-key", "expired", "unchanged"} {
		t.Run(kind, func(t *testing.T) {
			var replacement []byte
			var useReplacement bool
			source, err := NewRenewingServerCertificate(ca, []string{"localhost"}, func(csr []byte) ([]byte, error) {
				if useReplacement {
					return replacement, nil
				}
				return boundary.SignServerCertFromCSR(der, key, csr, []string{"localhost"}, time.Minute)
			})
			if err != nil {
				t.Fatal(err)
			}
			defer source.Close()
			before := source.current.Load()
			switch kind {
			case "malformed":
				replacement = []byte("not a certificate")
			case "prefix", "suffix", "private":
				for _, part := range before.Certificate {
					replacement = append(replacement, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: part})...)
				}
				if kind == "prefix" {
					replacement = append([]byte("untrusted-prefix\n"), replacement...)
				}
				if kind == "suffix" {
					replacement = append(replacement, []byte("untrusted-suffix")...)
				}
				if kind == "private" {
					replacement = append(replacement, []byte("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n")...)
				}
			case "empty":
				replacement = []byte{}
			case "wrong-ca":
				replacement, err = boundary.SignServerCertFromCSR(otherDER, otherKey, source.csr, []string{"localhost"}, 2*time.Minute)
			case "wrong-host":
				replacement, err = boundary.SignServerCertFromCSR(der, key, source.csr, []string{"wrong.example"}, 2*time.Minute)
			case "wrong-key":
				another, genErr := GenerateAgentKey("other")
				if genErr != nil {
					t.Fatal(genErr)
				}
				defer another.Destroy()
				csr, csrErr := another.CSR()
				if csrErr != nil {
					t.Fatal(csrErr)
				}
				replacement, err = boundary.SignServerCertFromCSR(der, key, csr, []string{"localhost"}, 2*time.Minute)
			case "expired":
				replacement, err = boundary.SignServerCertFromCSR(der, key, source.csr, []string{"localhost"}, -time.Second)
			case "unchanged":
				for _, part := range before.Certificate {
					replacement = append(replacement, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: part})...)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			useReplacement = true
			if err := source.renew(); err == nil {
				t.Fatal("invalid replacement accepted")
			}
			if source.current.Load() != before {
				t.Fatal("invalid replacement changed the served certificate")
			}
		})
	}
}

func FuzzRenewingServerCertificateReplacement(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"))
	f.Fuzz(func(t *testing.T, chain []byte) {
		if len(chain) > 128*1024 {
			t.Skip()
		}
		key, der, ca := renewingTestAuthority(t)
		var replace bool
		source, err := NewRenewingServerCertificate(ca, []string{"localhost"}, func(csr []byte) ([]byte, error) {
			if replace {
				return chain, nil
			}
			return boundary.SignServerCertFromCSR(der, key, csr, []string{"localhost"}, time.Hour)
		})
		if err != nil {
			t.Fatal(err)
		}
		defer source.Close()
		before := source.current.Load()
		replace = true
		if err := source.renew(); err != nil && source.current.Load() != before {
			t.Fatal("invalid input replaced current identity")
		}
	})
}
