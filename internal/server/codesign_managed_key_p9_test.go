// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/codesign"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/signing"
	"trstctl.com/trstctl/internal/store"
)

// p9HSM stands in for an HSM behind the signer's managed-key provider seam:
// keys are generated and used inside it, and it counts its signatures.
type p9HSM struct {
	mu    sync.Mutex
	keys  map[string]*crypto.LockedSigner
	signs int
}

type p9HSMSigner struct{ key *crypto.LockedSigner }

func (s p9HSMSigner) Public() crypto.PublicKey    { return s.key.Public() }
func (s p9HSMSigner) Algorithm() crypto.Algorithm { return s.key.Algorithm() }
func (s p9HSMSigner) Sign(message []byte, opts crypto.SignOptions) ([]byte, error) {
	digest, err := crypto.Digest(crypto.SHA256, message)
	if err != nil {
		return nil, err
	}
	return s.key.SignDigest(digest, opts)
}

func (h *p9HSM) GenerateManagedKey(_ context.Context, algorithm crypto.Algorithm) (crypto.Signer, crypto.KeyRef, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	key, err := crypto.GenerateLockedKey(algorithm)
	if err != nil {
		return nil, crypto.KeyRef{}, err
	}
	id := fmt.Sprintf("hsm-key-%d", len(h.keys)+1)
	h.keys[id] = key
	return p9HSMSigner{key: key}, crypto.KeyRef{ID: id, Algorithm: algorithm}, nil
}

func (h *p9HSM) RotateKey(ctx context.Context, ref crypto.KeyRef) (crypto.Signer, crypto.KeyRef, error) {
	return h.GenerateManagedKey(ctx, ref.Algorithm)
}
func (h *p9HSM) RevokeKey(context.Context, crypto.KeyRef) error  { return nil }
func (h *p9HSM) ZeroizeKey(context.Context, crypto.KeyRef) error { return nil }

func (h *p9HSM) SignManagedDigest(_ context.Context, ref crypto.KeyRef, digest []byte, opts crypto.SignOptions) ([]byte, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	key := h.keys[ref.ID]
	if key == nil {
		return nil, errors.New("unknown key")
	}
	h.signs++
	return key.SignDigest(digest, opts)
}

func (h *p9HSM) signCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.signs
}

// serveSignerWithHSM starts an isolated signer with the stand-in HSM as its
// managed-key provider and an independent sign authorizer.
func serveSignerWithHSM(t *testing.T, authorizer *crypto.SignAuthorizer, hsm *p9HSM) *signing.Client {
	t.Helper()
	dir, err := os.MkdirTemp("", "p9hsm")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socket := filepath.Join(dir, "s.sock")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	server := signing.NewServer(signing.WithAuthorizer(authorizer),
		signing.WithManagedKeyProviders(filepath.Join(dir, "journal"), map[string]crypto.RemoteKeyLifecycle{"pkcs11": hsm}))
	go func() {
		done <- signing.ServeServerWithOptions(ctx, socket, server, signing.ServeOptions{AllowInsecureDevNonLinux: runtime.GOOS != "linux"})
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("signer server did not stop")
		}
	})
	client, err := signing.DialReady(ctx, socket, 10*time.Second)
	if err != nil {
		t.Fatalf("dial the signer: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

// P9 (part 3b): a code-signing key held in an HSM — an Enterprise managed key —
// binds through the isolated signer for the code-signing purpose: its chain is
// checked against it, a certificate request is signed inside the HSM, the
// served sign path signs once per command (the signer journals the signature
// by operation id), and a revoked, mismatched or ambiguous configuration is
// refused at startup.
func TestCodeSigningWithAnHSMKeyP9(t *testing.T) {
	authorizer := testSignAuthorizer(t)
	hsm := &p9HSM{keys: map[string]*crypto.LockedSigner{}}
	client := serveSignerWithHSM(t, authorizer, hsm)
	ctx := context.Background()
	created, err := client.ManageKey(ctx, signing.ManagedKeyCommand{
		TenantID: servedTestTenant, Provider: "pkcs11", OperationID: "p9-hsm-generate",
		Action: signing.ManagedKeyGenerate, Algorithm: crypto.ECDSAP256,
	})
	if err != nil {
		t.Fatalf("generate the HSM key: %v", err)
	}
	record := store.ManagedKey{
		TenantID: servedTestTenant, Provider: "pkcs11", KeyID: created.KeyID, Algorithm: string(crypto.ECDSAP256),
		State: "active", PublicDER: created.PublicDER,
	}
	lookup := func(_ context.Context, tenantID, provider, keyID string) (store.ManagedKey, error) {
		if tenantID != record.TenantID || provider != record.Provider || keyID != record.KeyID {
			return store.ManagedKey{}, errors.New("no such managed key")
		}
		return record, nil
	}

	// A certificate request signed inside the HSM, issued by the operator's CA.
	hsmSigner, err := client.SignerForManagedKey(servedTestTenant, "pkcs11", created.KeyID, crypto.ECDSAP256, created.PublicDER, signing.PurposeCodeSign, authorizer)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: "release signer (HSM)", RequestedEKUs: []string{"codeSigning"}}, hsmSigner)
	if err != nil || crypto.VerifyCertificateRequest(csr) != nil {
		t.Fatalf("a CSR signed in the HSM: %v", err)
	}
	ca := newP9CA(t)
	chainFile := filepath.Join(t.TempDir(), "hsm-chain.pem")
	if err := os.WriteFile(chainFile, append(crypto.EncodeCertificatePEM(ca.issue(t, csr, "codeSigning")), crypto.EncodeCertificatePEM(ca.rootDER)...), 0o600); err != nil {
		t.Fatal(err)
	}
	keyCfg := config.CodeSigningKey{
		TenantID: servedTestTenant, ID: "release-hsm", Algorithm: "ecdsa-p256",
		ManagedKeyProvider: "pkcs11", ManagedKeyID: created.KeyID, CertificateChainFile: chainFile,
	}
	logKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(logKey.Destroy)
	logKeyPath := filepath.Join(t.TempDir(), "rekor-log-public.pem")
	if err := os.WriteFile(logKeyPath, crypto.MarshalPublicKeyPEM(logKey.Public().DER), 0o600); err != nil {
		t.Fatal(err)
	}
	rekor := config.CodeSigningRekor{Endpoint: "https://rekor.example.test/api/v1/log/entries", LogPublicKeyFile: logKeyPath}
	compose := func(keys ...config.CodeSigningKey) (CodeSigningConfig, error) {
		return codeSigningConfigFromConfig(ctx, config.CodeSigning{Enabled: true, Keys: keys, Rekor: rekor}, signing.StaticProvider{C: client}, authorizer, nil, lookup)
	}
	composed, err := compose(keyCfg)
	if err != nil {
		t.Fatalf("compose an HSM code-signing key: %v", err)
	}
	bound, err := composed.Keys.Signer(servedTestTenant, "release-hsm")
	if err != nil || !bytes.Equal(bound.Public().DER, created.PublicDER) {
		t.Fatalf("bound HSM key = %v", err)
	}
	if _, ok := bound.(codesign.OperationDigestSigner); !ok {
		t.Fatal("the HSM key cannot journal signatures by operation, which the served path requires")
	}
	if len(composed.KeyCertificates[codeSigningKeyIdentity(servedTestTenant, "release-hsm")]) != 2 {
		t.Fatal("the HSM key's chain was not loaded")
	}
	for name, change := range map[string]func(*config.CodeSigningKey){
		"with a handle":        func(k *config.CodeSigningKey) { k.Handle = "codesign-x" },
		"with create":          func(k *config.CodeSigningKey) { k.CreateIfMissing = true },
		"without an id":        func(k *config.CodeSigningKey) { k.ManagedKeyID = "" },
		"another algorithm":    func(k *config.CodeSigningKey) { k.Algorithm = "rsa-2048" },
		"an unknown key":       func(k *config.CodeSigningKey) { k.ManagedKeyID = "hsm-key-404" },
		"another tenant's key": func(k *config.CodeSigningKey) { k.TenantID = "7a0e3c55-9b1d-4f6e-8c2a-5d4b3e2f1a09" },
	} {
		bad := keyCfg
		bad.CertificateChainFile = ""
		change(&bad)
		if _, err := compose(bad); err == nil {
			t.Fatalf("an HSM key %s was accepted", name)
		}
	}
	record.State = "revoked"
	if _, err := compose(keyCfg); err == nil || !strings.Contains(err.Error(), "not active") {
		t.Fatalf("a revoked HSM key = %v", err)
	}
	record.State = "active"
	if _, err := codeSigningConfigFromConfig(ctx, config.CodeSigning{Enabled: true, Keys: []config.CodeSigningKey{keyCfg}, Rekor: rekor}, signing.StaticProvider{C: client}, nil, nil, lookup); err == nil {
		t.Fatal("an HSM key was bound without an independent sign authorizer")
	}

	// The served sign path: one HSM signature per command, replayed on retry.
	// The transparency log is the test fixture: the composed client would
	// publish to the configured Rekor endpoint.
	composed.TransparencyHandler = &rekorFixture{}
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) { d.CodeSigning = composed })
	startServedExternalCADispatcher(t, h)
	token := seedServedAPIToken(t, ctx, h.store, h.tenant, "release-bot", []string{string(authz.KeysRead), string(authz.KeysWrite)})
	digest := crypto.SHA256Sum([]byte("an artifact signed in the HSM"))
	before := hsm.signCount()
	status, body := doBearer(t, h.ts, http.MethodPost, "/api/v1/code-signing/sign", token, "p9-hsm-sign", map[string]any{
		"key_id": "release-hsm", "artifact_type": "pkcs11:CKM_ECDSA_SHA256", "digest": digest,
	})
	var signed struct {
		Signature    []byte `json:"signature"`
		PublicKeyDER []byte `json:"public_key_der"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &signed) != nil {
		t.Fatalf("sign with the HSM key: HTTP %d %s", status, body)
	}
	if err := crypto.VerifyDigest(crypto.PublicKey{Algorithm: crypto.ECDSAP256, DER: created.PublicDER}, digest, signed.Signature, crypto.SignOptions{Hash: crypto.SHA256}); err != nil {
		t.Fatalf("the HSM signature does not verify: %v", err)
	}
	if again, againBody := doBearer(t, h.ts, http.MethodPost, "/api/v1/code-signing/sign", token, "p9-hsm-sign", map[string]any{
		"key_id": "release-hsm", "artifact_type": "pkcs11:CKM_ECDSA_SHA256", "digest": digest,
	}); again != http.StatusOK || !bytes.Equal(againBody, body) {
		t.Fatalf("a repeated command = HTTP %d %s", again, againBody)
	}
	if signs := hsm.signCount() - before; signs != 1 {
		t.Fatalf("the HSM signed %d times for one command", signs)
	}
	if status, body := secretsReq(t, h, http.MethodGet, "/api/v1/code-signing/keys/release-hsm/certificate", token, nil); status != http.StatusOK || !bytes.Contains(body, []byte(`"code_signing_eku":true`)) {
		t.Fatalf("the HSM key's chain: HTTP %d %s", status, body)
	}
}
