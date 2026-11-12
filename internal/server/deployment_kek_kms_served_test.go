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
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/crypto/kmswrap"
	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/signing"
	"trstctl.com/trstctl/internal/store"
)

// TestServedDeploymentKEKUnderACloudKMSKeyOD10: A198 with the OD-10 custody.
// The operator rotates the deployment KEK onto a kms wrapper the isolated
// signer keeps under a cloud KMS key with a cache time limit; the signer
// creates the new generation's key through it, and afterwards every stored
// credential of a tenant without its own domain is unwrapped by the signer
// without another KMS call while the key is held. When the signer's custody
// shuts down (the held key wiped), those credentials stop opening; nothing
// falls back to the key file.
func TestServedDeploymentKEKUnderACloudKMSKeyOD10(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	command, logFile, _ := servedKMSAdapter(t, root)
	st := newServerTestStore(t)
	if err := st.UpsertTenant(ctx, store.Tenant{TenantID: deploymentKEKOperatorTenant, Name: "deployment-kek-kms", EventSeq: 1}); err != nil {
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
	cfg.Secrets.TenantSealKMSWrappers = []config.TenantSealKMSWrapper{{ID: "kms-a"}}

	adapter, err := kmswrap.NewExternalKMSWrapper(kmswrap.ExternalKMSConfig{Provider: "awskms",
		KeyRef: "arn:aws:kms:us-east-1:111122223333:key/deployment-kek", WrapCommand: command, Timeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := kmswrap.CreateWrapperKey(adapter)
	if err != nil {
		t.Fatal(err)
	}
	key, err := kmswrap.NewWrapperKey(adapter, wrapped, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Close)
	custody := &kmsCustodyDouble{keys: map[string]*kmswrap.WrapperKey{"kms-a": key}}
	authz, err := signing.LoadOrCreateAuthorizer(filepath.Join(root, "signer-auth.bin"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(authz.Destroy)
	socketDir, err := os.MkdirTemp("", "dk-kms-")
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

	if rec := servedTenantSealRequest(t, srv, token, http.MethodPost, "/api/v1/secrets/store", "deployment-kek-kms-secret",
		[]byte(`{"name":"db/password","value":"kms-protected-secret"}`)); rec.Code != http.StatusCreated {
		t.Fatalf("create secret = %d body=%s", rec.Code, rec.Body.String())
	}
	if rec := servedTenantSealRequest(t, srv, token, http.MethodPost, "/api/v1/platform/deployment-kek/rotate", "deployment-kek-kms-rotate",
		[]byte(`{"wrapper_kind":"kms","wrapper_id":"kms-a"}`)); rec.Code != http.StatusAccepted {
		t.Fatalf("rotate onto the signer's kms wrapper = %d body=%s", rec.Code, rec.Body.String())
	}
	servedStepDeploymentKEK(t, deps, nil)
	status := servedDeploymentKEKStatus(t, srv, token)
	if status.Generation != 1 || status.Custody != "kms" || status.WrapperID != "kms-a" || status.Rotation == nil ||
		status.Rotation.Status != "completed" || status.Rotation.ContainersRewrapped == 0 {
		t.Fatalf("status = %+v rotation=%+v", status, status.Rotation)
	}
	servedRequireDeploymentGeneration(t, keyFile, "hot state under the kms generation",
		servedDeploymentHotStateContainers(t, st, deploymentKEKOperatorTenant), 1)

	// Every read is unwrapped by the signer, and the held key means no KMS call.
	before := servedKMSUnwraps(t, logFile)
	for i := 0; i < 3; i++ {
		if rec := servedTenantSealRequest(t, srv, token, http.MethodGet, "/api/v1/secrets/store/db/password", "", nil); rec.Code != http.StatusOK ||
			!strings.Contains(rec.Body.String(), "kms-protected-secret") {
			t.Fatalf("read %d through the signer = %d body=%s", i, rec.Code, rec.Body.String())
		}
	}
	if after := servedKMSUnwraps(t, logFile); after != before || key.Unwraps() != 1 {
		t.Fatalf("three reads made %d KMS unwraps (key unwraps %d); want the one held key", after-before, key.Unwraps())
	}

	key.Close()
	if rec := servedTenantSealRequest(t, srv, token, http.MethodGet, "/api/v1/secrets/store/db/password", "", nil); rec.Code == http.StatusOK ||
		strings.Contains(rec.Body.String(), "kms-protected-secret") {
		t.Fatalf("a secret opened after the signer wiped the held key = %d body=%s", rec.Code, rec.Body.String())
	}
}
