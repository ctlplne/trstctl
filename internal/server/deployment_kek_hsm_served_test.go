// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/signing"
	"trstctl.com/trstctl/internal/store"
)

// TestServedDeploymentKEKUnderASignerHSMKey: A198 with the A123 custody. The
// operator rotates the deployment KEK onto an HSM key the isolated signer
// holds; the signer creates the new generation's key, and afterwards every
// stored credential of a tenant without its own domain is unwrapped by the
// signer. When the signer loses the HSM key, those credentials stop opening;
// nothing falls back to the key file.
func TestServedDeploymentKEKUnderASignerHSMKey(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	st := newServerTestStore(t)
	if err := st.UpsertTenant(ctx, store.Tenant{TenantID: deploymentKEKOperatorTenant, Name: "deployment-kek-hsm", EventSeq: 1}); err != nil {
		t.Fatal(err)
	}
	token := seedScopedToken(t, st, deploymentKEKOperatorTenant, "keys:read", "keys:write", "secrets:read", "secrets:write")

	cfg := config.Default()
	cfg.RateLimit.Enabled = false
	cfg.Secrets.EnableAPI = true
	cfg.Audit.SigningKeyFile = filepath.Join(root, "audit-signing-key.pem")
	cfg.Secrets.KEKFile = filepath.Join(root, "deployment-kek")
	cfg.Secrets.KEKOperatorTenantID = deploymentKEKOperatorTenant
	cfg.Secrets.KEKRotationSettle = "0s"
	cfg.Signer.AuthSecretFile = filepath.Join(root, "sign-auth.bin")
	cfg.Signer.KeyStoreDir = filepath.Join(root, "signer-keys")
	cfg.CA.CertFile = filepath.Join(root, "issuing-ca.crt")
	cfg.Secrets.TenantSealPKCS11Wrappers = []config.TenantSealPKCS11Wrapper{{ID: "hsm-a"}}

	hsmKey, err := crypto.RandomBytes(32)
	if err != nil {
		t.Fatal(err)
	}
	custody := &hsmCustodyDouble{keys: map[string][]byte{"hsm-a": hsmKey}}
	authz, err := signing.LoadOrCreateAuthorizer(filepath.Join(root, "signer-auth.bin"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(authz.Destroy)
	socketDir, err := os.MkdirTemp("", "dk-hsm-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(socketDir) })
	socket := filepath.Join(socketDir, "s.sock")
	signerCtx, stopSigner := context.WithCancel(ctx)
	served := make(chan error, 1)
	go func() {
		served <- signing.ServeServerWithOptions(signerCtx,
			socket, signing.NewServer(signing.WithAuthorizer(authz), signing.WithTenantKEKCustody(custody)),
			signing.ServeOptions{AllowInsecureDevNonLinux: runtime.GOOS != "linux"})
	}()
	t.Cleanup(func() {
		stopSigner()
		if err := <-served; err != nil {
			t.Errorf("serve signer: %v", err)
		}
	})
	client, err := signing.DialReady(ctx, socket, 10*time.Second)
	if err != nil {
		t.Fatalf("dial signer: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	auditKey, err := jose.GenerateRSASigningKey("audit-export")
	if err != nil {
		t.Fatal(err)
	}
	log, err := openHistoryAwareEventLog(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: filepath.Join(root, "nats")}, st, auditKey)
	if err != nil {
		t.Fatal(err)
	}
	guard, err := egressGuardFromConfig(cfg.AirGap)
	if err != nil {
		_ = log.Close()
		t.Fatal(err)
	}
	secrets, err := loadRunSecrets(cfg)
	if err != nil {
		_ = log.Close()
		t.Fatal(err)
	}
	t.Cleanup(secrets.Close)
	keyFile, ok := secrets.kek.(*seal.LocalKEK)
	if !ok {
		t.Fatalf("run secrets hold %T, want the key file", secrets.kek)
	}
	signer := runSigner{signer: signing.StaticProvider{C: client}, tokenProvider: authz, topology: config.SignerExternal}
	deps, err := buildRunDeps(ctx, cfg, st, log, signer, secrets, slog.New(slog.NewTextHandler(io.Discard, nil)), guard, auditKey)
	if err != nil {
		_ = log.Close()
		t.Fatalf("production buildRunDeps: %v", err)
	}
	srv, err := Build(ctx, deps)
	if err != nil {
		_ = log.Close()
		t.Fatalf("Build: %v", err)
	}
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })

	if rec := servedTenantSealRequest(t, srv, token, http.MethodPost, "/api/v1/secrets/store", "deployment-kek-hsm-secret",
		[]byte(`{"name":"db/password","value":"hsm-protected-secret"}`)); rec.Code != http.StatusCreated {
		t.Fatalf("create secret = %d body=%s", rec.Code, rec.Body.String())
	}
	if rec := servedTenantSealRequest(t, srv, token, http.MethodPost, "/api/v1/platform/deployment-kek/rotate", "deployment-kek-hsm-rotate",
		[]byte(`{"wrapper_kind":"pkcs11","wrapper_id":"hsm-a"}`)); rec.Code != http.StatusAccepted {
		t.Fatalf("rotate onto the signer's HSM key = %d body=%s", rec.Code, rec.Body.String())
	}
	if creates, _, _, _ := custody.calls(); creates != 1 {
		t.Fatalf("the signer created %d keys for the next generation, want 1", creates)
	}
	servedStepDeploymentKEK(t, deps, nil)
	status := servedDeploymentKEKStatus(t, srv, token)
	if status.Generation != 1 || status.Custody != "pkcs11" || status.WrapperID != "hsm-a" || status.Rotation == nil ||
		status.Rotation.Status != "completed" || status.Rotation.ContainersRewrapped == 0 {
		t.Fatalf("status = %+v rotation=%+v", status, status.Rotation)
	}
	servedRequireDeploymentGeneration(t, keyFile, "hot state under the HSM generation",
		servedDeploymentHotStateContainers(t, st, deploymentKEKOperatorTenant), 1)

	_, _, _, unwrapsBefore := custody.calls()
	if rec := servedTenantSealRequest(t, srv, token, http.MethodGet, "/api/v1/secrets/store/db/password", "", nil); rec.Code != http.StatusOK ||
		!strings.Contains(rec.Body.String(), "hsm-protected-secret") {
		t.Fatalf("read through the signer = %d body=%s", rec.Code, rec.Body.String())
	}
	if _, _, _, unwraps := custody.calls(); unwraps <= unwrapsBefore {
		t.Fatalf("the read did not unwrap through the signer: unwraps %d→%d", unwrapsBefore, unwraps)
	}

	custody.mu.Lock()
	delete(custody.keys, "hsm-a")
	custody.mu.Unlock()
	if rec := servedTenantSealRequest(t, srv, token, http.MethodGet, "/api/v1/secrets/store/db/password", "", nil); rec.Code == http.StatusOK ||
		strings.Contains(rec.Body.String(), "hsm-protected-secret") {
		t.Fatalf("a secret opened after the signer lost the HSM key = %d body=%s", rec.Code, rec.Body.String())
	}
}
