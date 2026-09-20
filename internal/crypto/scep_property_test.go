// SPDX-License-Identifier: BUSL-1.1

package crypto_test

import (
	"bytes"
	"math/rand"
	"reflect"
	"testing"
	"testing/quick"
	"time"

	trstcrypto "trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
)

const scepPropertySeed int64 = 81003

type scepPropertyInput struct {
	CommonName    string
	TransactionID string
}

func (scepPropertyInput) Generate(r *rand.Rand, size int) reflect.Value {
	return reflect.ValueOf(scepPropertyInput{
		CommonName:    "device-" + scepPropertyToken(r, 1+minSCEPProperty(size, 24)),
		TransactionID: "txn-" + scepPropertyToken(r, 1+minSCEPProperty(size, 40)),
	})
}

type scepPropertyFixture struct {
	caSigner       *trstcrypto.LockedSigner
	clientSigner   *trstcrypto.LockedSigner
	caCertDER      []byte
	clientCertDER  []byte
	caKeyPKCS8     []byte
	clientKeyPKCS8 []byte
}

func newSCEPPropertyFixture(t *testing.T) *scepPropertyFixture {
	t.Helper()
	caSigner, err := trstcrypto.GenerateLockedKey(trstcrypto.RSA2048)
	if err != nil {
		t.Fatalf("generate SCEP property CA key: %v", err)
	}
	t.Cleanup(caSigner.Destroy)
	clientSigner, err := trstcrypto.GenerateLockedKey(trstcrypto.RSA2048)
	if err != nil {
		t.Fatalf("generate SCEP property client key: %v", err)
	}
	t.Cleanup(clientSigner.Destroy)

	caCertDER, err := trstcrypto.SelfSignedCACert(caSigner, "SCEP property CA", time.Hour)
	if err != nil {
		t.Fatalf("create SCEP property CA certificate: %v", err)
	}
	clientCertDER, err := trstcrypto.SelfSignedCACert(clientSigner, "SCEP property client", time.Hour)
	if err != nil {
		t.Fatalf("create SCEP property client certificate: %v", err)
	}
	caKeyPKCS8, err := caSigner.PKCS8()
	if err != nil {
		t.Fatalf("export SCEP property CA key: %v", err)
	}
	t.Cleanup(func() { secret.Wipe(caKeyPKCS8) })
	clientKeyPKCS8, err := clientSigner.PKCS8()
	if err != nil {
		t.Fatalf("export SCEP property client key: %v", err)
	}
	t.Cleanup(func() { secret.Wipe(clientKeyPKCS8) })

	return &scepPropertyFixture{
		caSigner:       caSigner,
		clientSigner:   clientSigner,
		caCertDER:      caCertDER,
		clientCertDER:  clientCertDER,
		caKeyPKCS8:     caKeyPKCS8,
		clientKeyPKCS8: clientKeyPKCS8,
	}
}

// TestPropertySCEPRequestResponseRoundTrip generates semantic PKCSReq/CertRep
// exchanges. CMS wrapping, decryption, signed attributes, the inner PKCS#10,
// and the issued certificate must all survive the round trip without drift.
func TestPropertySCEPRequestResponseRoundTrip(t *testing.T) {
	fixture := newSCEPPropertyFixture(t)
	prop := func(g scepPropertyInput) bool {
		csrDER, err := trstcrypto.CreateCertificateRequest(trstcrypto.CertificateRequestTemplate{
			CommonName: g.CommonName,
			DNSNames:   []string{g.CommonName + ".example.test"},
		}, fixture.clientSigner)
		if err != nil {
			t.Logf("create generated SCEP CSR: %v", err)
			return false
		}
		requestDER, err := trstcrypto.BuildSCEPRequest(
			csrDER,
			fixture.clientCertDER,
			fixture.clientKeyPKCS8,
			fixture.caCertDER,
			g.TransactionID,
		)
		if err != nil {
			t.Logf("build generated SCEP request: %v", err)
			return false
		}
		request, err := trstcrypto.ParseSCEPRequest(requestDER, fixture.caCertDER, fixture.caKeyPKCS8)
		if err != nil {
			t.Logf("parse generated SCEP request: %v", err)
			return false
		}
		if request.MessageType != trstcrypto.SCEPMessagePKCSReq || request.TransactionID != g.TransactionID || len(request.SenderNonce) != 16 || !bytes.Equal(request.CSRDER, csrDER) {
			t.Logf("generated SCEP request changed: got=%+v transaction=%q csr_equal=%t", request, g.TransactionID, bytes.Equal(request.CSRDER, csrDER))
			return false
		}
		if err := trstcrypto.VerifyCertificateRequest(request.CSRDER); err != nil {
			t.Logf("round-tripped SCEP CSR no longer verifies: %v", err)
			return false
		}

		issuedDER, err := trstcrypto.SignLeafFromCSR(fixture.caCertDER, fixture.caSigner, csrDER, time.Minute)
		if err != nil {
			t.Logf("sign generated SCEP leaf: %v", err)
			return false
		}
		replyDER, err := trstcrypto.BuildSCEPSuccess(issuedDER, fixture.caCertDER, fixture.caKeyPKCS8, request)
		if err != nil {
			t.Logf("build generated SCEP success: %v", err)
			return false
		}
		parsedIssuedDER, err := trstcrypto.ParseSCEPResponse(replyDER, fixture.clientCertDER, fixture.clientKeyPKCS8)
		if err != nil {
			t.Logf("parse generated SCEP response: %v", err)
			return false
		}
		if !bytes.Equal(parsedIssuedDER, issuedDER) {
			t.Logf("SCEP CertRep changed issued certificate: got=%x want=%x", parsedIssuedDER, issuedDER)
			return false
		}
		return true
	}

	if err := quick.Check(prop, &quick.Config{
		MaxCount: 32,
		Rand:     rand.New(rand.NewSource(scepPropertySeed)), // #nosec G404 -- deterministic property-test stream, not security randomness (CWE-338)
	}); err != nil {
		t.Fatalf("SCEP request/response round-trip property violated: %v", err)
	}
}

// TestPropertySCEPRejectsCorruptedCSR proves the outer CMS signature cannot make
// a damaged inner PKCS#10 trustworthy. The parser must return nil plus an error.
func TestPropertySCEPRejectsCorruptedCSR(t *testing.T) {
	fixture := newSCEPPropertyFixture(t)
	prop := func(g scepPropertyInput) bool {
		csrDER, err := trstcrypto.CreateCertificateRequest(trstcrypto.CertificateRequestTemplate{CommonName: g.CommonName}, fixture.clientSigner)
		if err != nil {
			t.Logf("create generated SCEP CSR: %v", err)
			return false
		}
		corruptCSR := bytes.Clone(csrDER)
		corruptCSR[len(corruptCSR)-1] ^= 0x01
		requestDER, err := trstcrypto.BuildSCEPRequest(
			corruptCSR,
			fixture.clientCertDER,
			fixture.clientKeyPKCS8,
			fixture.caCertDER,
			g.TransactionID,
		)
		if err != nil {
			t.Logf("wrap generated corrupted SCEP CSR: %v", err)
			return false
		}
		request, err := trstcrypto.ParseSCEPRequest(requestDER, fixture.caCertDER, fixture.caKeyPKCS8)
		if err == nil || request != nil {
			t.Logf("corrupted SCEP CSR accepted: request=%+v err=%v", request, err)
			return false
		}
		return true
	}

	if err := quick.Check(prop, &quick.Config{
		MaxCount: 32,
		Rand:     rand.New(rand.NewSource(scepPropertySeed + 1)), // #nosec G404 -- deterministic property-test stream, not security randomness (CWE-338)
	}); err != nil {
		t.Fatalf("SCEP corrupted-CSR rejection property violated: %v", err)
	}
}

func scepPropertyToken(r *rand.Rand, n int) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = alphabet[r.Intn(len(alphabet))]
	}
	return string(b)
}

func minSCEPProperty(a, b int) int {
	if a < b {
		return a
	}
	return b
}
