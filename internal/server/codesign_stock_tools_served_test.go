// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/events"
)

// p9CA is the operator's CA in these tests: it answers a code-signing key's
// certificate request the way any CA would.
type p9CA struct {
	key     *crypto.LockedSigner
	rootDER []byte
}

func newP9CA(t *testing.T) p9CA {
	t.Helper()
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Destroy)
	root, err := crypto.SelfSignedCACert(key, "P9 code-signing root", 48*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return p9CA{key: key, rootDER: root}
}

func (ca p9CA) issue(t *testing.T, csrDER []byte, eku string) []byte {
	t.Helper()
	leaf, err := crypto.SignLeafFromCSRWithProfile(ca.rootDER, ca.key, csrDER, 24*time.Hour, crypto.LeafProfile{
		AllowedKeyUsages: &crypto.KeyUsages{DigitalSignature: true}, AllowedExtKeyUsage: []string{eku},
	})
	if err != nil {
		t.Fatal(err)
	}
	return leaf
}

// P9 (part 1): a managed code-signing key gets a certificate request signed
// inside the signer and serves the chain an operator's CA issued for it, and
// the Notation plugin built from clients/signing signs through the running
// API — the signature verifies against the served leaf, the key never leaves
// the signer, and a principal that may not sign is stopped.
func TestServedCodeSigningStockToolsP9(t *testing.T) {
	signingKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(signingKey.Destroy)
	bareKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(bareKey.Destroy)
	ca := newP9CA(t)
	csrDER, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{
		CommonName: "release signer", RequestedEKUs: []string{"codeSigning"},
	}, signingKey)
	if err != nil {
		t.Fatal(err)
	}
	leafDER := ca.issue(t, csrDER, "codeSigning")
	chainPEM := append(crypto.EncodeCertificatePEM(leafDER), crypto.EncodeCertificatePEM(ca.rootDER)...)

	// Startup accepts a chain only when its leaf names the key and may sign code.
	chain, err := loadCodeSigningKeyChain(chainPEM, signingKey)
	if err != nil || len(chain) != 2 {
		t.Fatalf("load the configured chain: %d certificates, %v", len(chain), err)
	}
	if _, err := loadCodeSigningKeyChain(chainPEM, bareKey); err == nil || !strings.Contains(err.Error(), "does not name this key") {
		t.Fatalf("a chain for another key was accepted: %v", err)
	}
	if _, err := loadCodeSigningKeyChain(crypto.EncodeCertificatePEM(ca.issue(t, csrDER, "serverAuth")), signingKey); err == nil || !strings.Contains(err.Error(), "codeSigning") {
		t.Fatalf("a TLS server leaf was accepted for code signing: %v", err)
	}
	if _, err := loadCodeSigningKeyChain([]byte("no certificate here"), signingKey); err == nil {
		t.Fatal("a file without a certificate was accepted")
	}

	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.CodeSigning = CodeSigningConfig{
			Keys: codeSigningKeyMap{keys: map[string]crypto.DigestSigner{
				"release-key": testOperationDigestSigner{DigestSigner: signingKey},
				"bare-key":    testOperationDigestSigner{DigestSigner: bareKey},
			}},
			KeyCertificates: map[string][][]byte{codeSigningKeyIdentity(servedTestTenant, "release-key"): chain},
		}
	})
	startServedExternalCADispatcher(t, h)
	signer := seedServedAPIToken(t, context.Background(), h.store, h.tenant, "release-bot", []string{
		string(authz.KeysRead), string(authz.KeysWrite),
	})
	reader := seedServedAPIToken(t, context.Background(), h.store, h.tenant, "release-reader", []string{string(authz.KeysRead)})

	status, body := secretsReq(t, h, http.MethodGet, "/api/v1/code-signing/keys/release-key/certificate", reader, nil)
	var served api.CodeSigningKeyCertificate
	if status != http.StatusOK || json.Unmarshal(body, &served) != nil {
		t.Fatalf("certificate: HTTP %d %s", status, body)
	}
	leafInfo, err := certinfo.Inspect(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	if served.KeyID != "release-key" || served.Algorithm != string(crypto.ECDSAP256) || !served.CodeSigningEKU ||
		!bytes.Equal(served.PublicKeyDER, signingKey.Public().DER) || served.ChainPEM != string(chainPEM) ||
		served.LeafFingerprint != leafInfo.SHA256Fingerprint || !served.NotAfter.Equal(leafInfo.NotAfter) {
		t.Fatalf("served certificate = %+v", served)
	}
	if bytes.Contains(body, []byte("PRIVATE")) {
		t.Fatal("the certificate response carries private material")
	}
	for path, want := range map[string]int{
		"/api/v1/code-signing/keys/bare-key/certificate":    http.StatusNotFound,
		"/api/v1/code-signing/keys/missing-key/certificate": http.StatusNotFound,
	} {
		if status, body := secretsReq(t, h, http.MethodGet, path, reader, nil); status != want {
			t.Fatalf("%s: HTTP %d %s, want %d", path, status, body, want)
		}
	}
	if status, _ := secretsReq(t, h, http.MethodGet, "/api/v1/code-signing/keys/release-key/certificate", "", nil); status != http.StatusUnauthorized {
		t.Fatalf("an anonymous read: HTTP %d", status)
	}

	// The certificate request is signed inside the signer; a CA issuing from it
	// names the managed key.
	if status, _ := secretsReqKey(t, h, http.MethodPost, "/api/v1/code-signing/keys/release-key/csr", reader, "p9-csr-read-only", map[string]string{"common_name": "release signer"}); status != http.StatusForbidden {
		t.Fatalf("a read-only principal got a CSR: HTTP %d", status)
	}
	if status, _ := secretsReqKey(t, h, http.MethodPost, "/api/v1/code-signing/keys/release-key/csr", signer, "p9-csr-empty", map[string]string{"common_name": " "}); status != http.StatusBadRequest {
		t.Fatalf("a CSR without a subject: HTTP %d", status)
	}
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/code-signing/keys/release-key/csr", signer, "p9-csr", map[string]string{"common_name": "release signer 2027"})
	var csr api.CodeSigningKeyCSR
	if status != http.StatusOK || json.Unmarshal(body, &csr) != nil || csr.KeyID != "release-key" {
		t.Fatalf("csr: HTTP %d %s", status, body)
	}
	servedCSR, csrInfo, err := crypto.ParsePublicCSRPEM([]byte(csr.CSRPEM))
	if err != nil || crypto.VerifyCertificateRequest(servedCSR) != nil || csrInfo.CommonName != "release signer 2027" ||
		len(csrInfo.RequestedEKUs) != 1 || csrInfo.RequestedEKUs[0] != "codeSigning" {
		t.Fatalf("served CSR = %+v, %v", csrInfo, err)
	}
	if _, err := loadCodeSigningKeyChain(crypto.EncodeCertificatePEM(ca.issue(t, servedCSR, "codeSigning")), signingKey); err != nil {
		t.Fatalf("a certificate issued from the served CSR does not name the key: %v", err)
	}

	// Notation's plugin, built from clients/signing, signs through the API.
	plugin := buildP9NotationPlugin(t)
	code, out, failure := runP9NotationPlugin(t, plugin, h, signer, "describe-key", map[string]any{"contractVersion": "1.0", "keyId": "release-key"})
	if code != 0 || !strings.Contains(string(out), `"keySpec":"EC-256"`) {
		t.Fatalf("describe-key = %d %s %s", code, out, failure)
	}
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","kid":"release-key","cty":"application/vnd.cncf.notary.payload.v1+json"}`))
	payload := `{"targetArtifact":{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:` + strings.Repeat("ab", 32) + `","size":527}}`
	signingInput := header + "." + base64.RawURLEncoding.EncodeToString([]byte(payload))
	before := countP9CodeSigningEvents(t, h)
	code, out, failure = runP9NotationPlugin(t, plugin, h, signer, "generate-signature", map[string]any{
		"contractVersion": "1.0", "keyId": "release-key", "keySpec": "EC-256", "hashAlgorithm": "SHA-256", "payload": []byte(signingInput),
	})
	var generated struct {
		KeyID            string   `json:"keyId"`
		Signature        []byte   `json:"signature"`
		SigningAlgorithm string   `json:"signingAlgorithm"`
		CertificateChain [][]byte `json:"certificateChain"`
	}
	if code != 0 || json.Unmarshal(out, &generated) != nil {
		t.Fatalf("generate-signature = %d %s %s", code, out, failure)
	}
	if generated.KeyID != "release-key" || generated.SigningAlgorithm != "ECDSA-SHA-256" || len(generated.Signature) != 64 ||
		len(generated.CertificateChain) != 2 || !bytes.Equal(generated.CertificateChain[0], leafDER) || !bytes.Equal(generated.CertificateChain[1], ca.rootDER) {
		t.Fatalf("generated = %+v", generated)
	}
	jwk, err := crypto.PublicJWK(signingKey.Public(), "release-key")
	if err != nil {
		t.Fatal(err)
	}
	jws := signingInput + "." + base64.RawURLEncoding.EncodeToString(generated.Signature)
	if claims, err := crypto.VerifyJWT(jws, crypto.JWKS{Keys: []crypto.JWK{jwk}}); err != nil || string(claims) != payload {
		t.Fatalf("Notation's signature does not verify against the served leaf's key: %v", err)
	}
	tampered := header + "." + base64.RawURLEncoding.EncodeToString([]byte(strings.Replace(payload, "527", "528", 1))) + "." + base64.RawURLEncoding.EncodeToString(generated.Signature)
	if _, err := crypto.VerifyJWT(tampered, crypto.JWKS{Keys: []crypto.JWK{jwk}}); err == nil {
		t.Fatal("the signature verified over a changed payload")
	}
	if after := countP9CodeSigningEvents(t, h); after <= before {
		t.Fatal("the plugin's signature did not go through the code-signing service's record")
	}

	// A principal that may not sign is stopped, and Notation is told why.
	code, out, failure = runP9NotationPlugin(t, plugin, h, reader, "generate-signature", map[string]any{
		"contractVersion": "1.0", "keyId": "release-key", "keySpec": "EC-256", "hashAlgorithm": "SHA-256", "payload": []byte(signingInput),
	})
	if code == 0 || len(out) != 0 || !strings.Contains(string(failure), `"errorCode":"ACCESS_DENIED"`) {
		t.Fatalf("a read-only principal signed: %d %s %s", code, out, failure)
	}
	if code, _, failure := runP9NotationPlugin(t, plugin, h, signer, "describe-key", map[string]any{"contractVersion": "1.0", "keyId": "bare-key"}); code == 0 || !strings.Contains(string(failure), "no certificate chain") {
		t.Fatalf("a key without a chain was offered to Notation: %d %s", code, failure)
	}
}

func countP9CodeSigningEvents(t *testing.T, h *servedHarness) int {
	t.Helper()
	count := 0
	if err := h.log.Replay(context.Background(), 0, func(event events.Event) error {
		if event.TenantID == h.tenant && strings.HasPrefix(event.Type, "codesign.") {
			count++
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return count
}

// buildP9NotationPlugin builds the plugin from its own module, as an operator
// would install it.
func buildP9NotationPlugin(t *testing.T) string {
	t.Helper()
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go not on PATH; cannot build the Notation plugin")
	}
	out := filepath.Join(t.TempDir(), "notation-trstctl")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, goBin, "build", "-o", out, "./cmd/notation-trstctl") // #nosec G204 -- test builds the in-repo plugin (CWE-78)
	cmd.Dir = filepath.Join("..", "..", "clients", "signing")
	cmd.Env = append(os.Environ(), "GOWORK=off", "GOPROXY=off")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build the Notation plugin: %v\n%s", err, output)
	}
	return out
}

func runP9NotationPlugin(t *testing.T, plugin string, h *servedHarness, token, command string, request any) (int, []byte, []byte) {
	t.Helper()
	raw, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, plugin, command) // #nosec G204 -- test runs the plugin it just built (CWE-78)
	cmd.Env = append(os.Environ(), "TRSTCTL_URL="+h.ts.URL, "TRSTCTL_TOKEN="+token, "TRSTCTL_TOKEN_FILE=", "TRSTCTL_CA_FILE=")
	cmd.Stdin = bytes.NewReader(raw)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		var exit *exec.ExitError
		if !errors.As(err, &exit) {
			t.Fatalf("run the Notation plugin: %v", err)
		}
		return exit.ExitCode(), stdout.Bytes(), stderr.Bytes()
	}
	return 0, stdout.Bytes(), stderr.Bytes()
}
