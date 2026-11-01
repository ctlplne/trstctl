// SPDX-License-Identifier: MPL-2.0

package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"trstctl.com/clients/signing/trstctlsign"
)

// fakeTrstctl stands in for the code-signing API: it holds the key, signs
// digests (ASN.1 DER, as trstctl's signer returns them) and serves the chain.
type fakeTrstctl struct {
	key       *ecdsa.PrivateKey
	certDER   []byte
	algorithm string
	signCode  int
	digests   [][]byte
}

func newFakeTrstctl(t *testing.T) *fakeTrstctl {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(9), Subject: pkix.Name{CommonName: "release signer"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return &fakeTrstctl{key: key, certDER: der, algorithm: "ECDSA-P256", signCode: http.StatusOK}
}

func (f *fakeTrstctl) client(t *testing.T) func() (*trstctlsign.Client, error) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/code-signing/keys/release/certificate":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"key_id": "release", "algorithm": f.algorithm, "code_signing_eku": true,
				"chain_pem": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.certDER})),
			})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/code-signing/sign":
			var req struct {
				Digest []byte `json:"digest"`
			}
			_ = json.NewDecoder(r.Body).Decode(&req)
			if f.signCode != http.StatusOK {
				w.WriteHeader(f.signCode)
				_, _ = w.Write([]byte(`{"detail":"approval_required:codesign:abc request_id=r1: the exact code-signing command awaits distinct approval"}`))
				return
			}
			f.digests = append(f.digests, req.Digest)
			sig, err := ecdsa.SignASN1(rand.Reader, f.key, req.Digest)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"algorithm": f.algorithm, "signature": sig})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return func() (*trstctlsign.Client, error) {
		return &trstctlsign.Client{BaseURL: srv.URL, Token: "tok", HTTP: srv.Client()}, nil
	}
}

func invoke(t *testing.T, newClient func() (*trstctlsign.Client, error), command string, request any) (int, map[string]any, map[string]any) {
	t.Helper()
	var stdin bytes.Buffer
	if request != nil {
		if err := json.NewEncoder(&stdin).Encode(request); err != nil {
			t.Fatal(err)
		}
	}
	var stdout, stderr bytes.Buffer
	code := run([]string{command}, &stdin, &stdout, &stderr, newClient)
	var out, failure map[string]any
	if stdout.Len() > 0 {
		if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
			t.Fatalf("stdout %q: %v", stdout.String(), err)
		}
	}
	if stderr.Len() > 0 {
		if err := json.Unmarshal(stderr.Bytes(), &failure); err != nil {
			t.Fatalf("stderr %q: %v", stderr.String(), err)
		}
	}
	return code, out, failure
}

func TestMetadataNamesThePluginAndItsCapability(t *testing.T) {
	code, out, _ := invoke(t, nil, "get-plugin-metadata", nil)
	if code != 0 || out["name"] != "trstctl" || !strings.Contains(stringsOf(out["capabilities"]), "SIGNATURE_GENERATOR.RAW") ||
		!strings.Contains(stringsOf(out["supportedContractVersions"]), "1.0") {
		t.Fatalf("metadata = %d %v", code, out)
	}
}

// A Notation signature through trstctl verifies against the configured leaf:
// the plugin hashes the payload, trstctl signs the digest inside its signer,
// and the plugin returns the raw r||s form with the certificate chain.
func TestGenerateSignatureVerifiesAgainstTheLeaf(t *testing.T) {
	fake := newFakeTrstctl(t)
	newClient := fake.client(t)
	code, out, failure := invoke(t, newClient, "describe-key", map[string]any{"contractVersion": "1.0", "keyId": "release"})
	if code != 0 || out["keySpec"] != "EC-256" || out["keyId"] != "release" {
		t.Fatalf("describe-key = %d %v %v", code, out, failure)
	}
	payload := []byte(`eyJhbGciOiJFUzI1NiJ9.eyJ0YXJnZXRBcnRpZmFjdCI6e319`)
	code, out, failure = invoke(t, newClient, "generate-signature", map[string]any{
		"contractVersion": "1.0", "keyId": "release", "keySpec": "EC-256", "hashAlgorithm": "SHA-256", "payload": payload,
	})
	if code != 0 {
		t.Fatalf("generate-signature = %d %v", code, failure)
	}
	raw := bytesOf(t, out["signature"])
	if len(raw) != 64 || out["signingAlgorithm"] != "ECDSA-SHA-256" || out["keyId"] != "release" {
		t.Fatalf("signature = %d bytes, %v", len(raw), out)
	}
	sum := sha256.Sum256(payload)
	if !ecdsa.Verify(&fake.key.PublicKey, sum[:], new(big.Int).SetBytes(raw[:32]), new(big.Int).SetBytes(raw[32:])) {
		t.Fatal("the plugin's signature does not verify against the key")
	}
	if len(fake.digests) != 1 || !bytes.Equal(fake.digests[0], sum[:]) {
		t.Fatal("trstctl was not asked to sign the payload's SHA-256 digest")
	}
	chain, _ := out["certificateChain"].([]any)
	if len(chain) != 1 || !bytes.Equal(bytesOf(t, chain[0]), fake.certDER) {
		t.Fatalf("certificate chain = %v", out["certificateChain"])
	}
}

// A denied or pending approval stops the signature, and Notation is told why.
func TestADeniedSignatureStopsNotation(t *testing.T) {
	fake := newFakeTrstctl(t)
	fake.signCode = http.StatusForbidden
	code, out, failure := invoke(t, fake.client(t), "generate-signature", map[string]any{
		"contractVersion": "1.0", "keyId": "release", "hashAlgorithm": "SHA-256", "payload": []byte("x"),
	})
	if code == 0 || out != nil || failure["errorCode"] != "ACCESS_DENIED" ||
		!strings.Contains(failure["errorMessage"].(string), "awaits distinct approval") {
		t.Fatalf("denied = %d %v %v", code, out, failure)
	}
}

func TestRefusals(t *testing.T) {
	fake := newFakeTrstctl(t)
	newClient := fake.client(t)
	for name, tc := range map[string]struct {
		command string
		request map[string]any
		code    string
	}{
		"contract":  {"describe-key", map[string]any{"contractVersion": "2.0", "keyId": "release"}, "UNSUPPORTED_CONTRACT_VERSION"},
		"hash":      {"generate-signature", map[string]any{"contractVersion": "1.0", "keyId": "release", "hashAlgorithm": "SHA-384", "payload": []byte("x")}, "VALIDATION_ERROR"},
		"command":   {"sign-everything", map[string]any{}, "VALIDATION_ERROR"},
		"no key id": {"describe-key", map[string]any{"contractVersion": "1.0"}, "VALIDATION_ERROR"},
	} {
		code, _, failure := invoke(t, newClient, tc.command, tc.request)
		if code == 0 || failure["errorCode"] != tc.code {
			t.Fatalf("%s: %d %v", name, code, failure)
		}
	}
	fake.algorithm = "RSA-3072"
	if code, _, failure := invoke(t, newClient, "describe-key", map[string]any{"contractVersion": "1.0", "keyId": "release"}); code == 0 || failure["errorCode"] != "VALIDATION_ERROR" {
		t.Fatalf("an RSA key was offered to Notation: %v", failure)
	}
	if len(fake.digests) != 0 {
		t.Fatal("a refused request reached the signer")
	}
}

func TestECDSADERToP1363PadsShortIntegers(t *testing.T) {
	der := []byte{0x30, 0x06, 0x02, 0x01, 0x05, 0x02, 0x01, 0x07}
	raw, err := ecdsaDERToP1363(der, 32)
	if err != nil || len(raw) != 64 || raw[31] != 5 || raw[63] != 7 || raw[0] != 0 {
		t.Fatalf("raw = %x, %v", raw, err)
	}
	if _, err := ecdsaDERToP1363(append(der, 0), 32); err == nil {
		t.Fatal("trailing bytes accepted")
	}
	if _, err := ecdsaDERToP1363([]byte{0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x07}, 32); err == nil {
		t.Fatal("a zero r accepted")
	}
}

func stringsOf(v any) string {
	list, _ := v.([]any)
	var out []string
	for _, item := range list {
		s, _ := item.(string)
		out = append(out, s)
	}
	return strings.Join(out, ",")
}

func bytesOf(t *testing.T, v any) []byte {
	t.Helper()
	s, _ := v.(string)
	var out []byte
	if err := json.Unmarshal([]byte(`"`+s+`"`), &out); err != nil {
		t.Fatalf("not base64: %v", v)
	}
	return out
}
