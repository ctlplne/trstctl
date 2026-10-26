// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/crypto/tenantwrap"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/signing"
	"trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/tenantseal"
)

// hsmCustodyDouble is the signer's tenant KEK custody with a software AES key
// standing in for each HSM key; the container and the per-call open are the
// real ones. It counts calls so the test can prove tenant data goes through
// the signer.
type hsmCustodyDouble struct {
	mu                             sync.Mutex
	keys                           map[string][]byte
	creates, opens, wraps, unwraps int
}

type hsmKeyDouble struct{ key []byte }

func (k hsmKeyDouble) Seal(plaintext, aad []byte) ([]byte, error) {
	return crypto.AESGCMSeal(k.key, plaintext, aad)
}

func (k hsmKeyDouble) Open(sealed, aad []byte) ([]byte, error) {
	plain, err := crypto.AESGCMOpen(k.key, sealed, aad)
	if err != nil {
		return nil, tenantwrap.ErrUnwrap
	}
	return plain, nil
}

func (c *hsmCustodyDouble) wrapper(id string, count *int) (tenantwrap.ExternalWrapper, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	*count++
	key, ok := c.keys[id]
	if !ok {
		return nil, signing.ErrTenantKEKWrapperUnknown
	}
	return hsmKeyDouble{key: key}, nil
}

func (c *hsmCustodyDouble) calls() (int, int, int, int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.creates, c.opens, c.wraps, c.unwraps
}

func (c *hsmCustodyDouble) CreateDomainKEK(_ context.Context, id string, binding []byte) ([]byte, error) {
	w, err := c.wrapper(id, &c.creates)
	if err != nil {
		return nil, err
	}
	kek, wrapped, err := tenantwrap.CreateDomainKEKExternal(w, binding)
	if err != nil {
		return nil, err
	}
	kek.Destroy()
	return wrapped, nil
}

func (c *hsmCustodyDouble) OpenDomainKEK(_ context.Context, id string, wrapped, binding []byte) error {
	w, err := c.wrapper(id, &c.opens)
	if err != nil {
		return err
	}
	kek, err := tenantwrap.OpenDomainKEKExternal(w, wrapped, binding)
	if err != nil {
		return err
	}
	kek.Destroy()
	return nil
}

func (c *hsmCustodyDouble) WrapDataKey(_ context.Context, id string, wrapped, binding, dataKey []byte) ([]byte, error) {
	w, err := c.wrapper(id, &c.wraps)
	if err != nil {
		return nil, err
	}
	kek, err := tenantwrap.OpenDomainKEKExternal(w, wrapped, binding)
	if err != nil {
		return nil, err
	}
	defer kek.Destroy()
	return kek.WrapDEK(dataKey)
}

func (c *hsmCustodyDouble) UnwrapDataKey(_ context.Context, id string, wrapped, binding, wrappedDataKey []byte) ([]byte, error) {
	w, err := c.wrapper(id, &c.unwraps)
	if err != nil {
		return nil, err
	}
	kek, err := tenantwrap.OpenDomainKEKExternal(w, wrapped, binding)
	if err != nil {
		return nil, err
	}
	defer kek.Destroy()
	return kek.UnwrapDEK(wrappedDataKey)
}

// A123 (owner decision 2026-10-26) through the default-binary composition: a
// tenant migrates to a pkcs11 wrapper the signer holds. The database keeps only
// the HSM-wrapped domain KEK, every tenant data key is wrapped and unwrapped by
// the signer, seal and unseal work as for a local wrapper, and when the signer
// loses the HSM key the tenant fails closed as wrapper_unavailable instead of
// falling back to the deployment KEK.
func TestServedTenantKeyDomainLivesInTheSignerUnderAnHSMKey(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	st := newServerTestStore(t)
	const hsmTenant = "55555555-5555-5555-5555-555555555555"
	if err := st.UpsertTenant(ctx, store.Tenant{TenantID: hsmTenant, Name: "tenant-hsm-served", EventSeq: 1}); err != nil {
		t.Fatal(err)
	}
	token := seedScopedToken(t, st, hsmTenant, "keys:read", "keys:write", "owners:read", "owners:write")

	cfg := config.Default()
	cfg.RateLimit.Enabled = false
	cfg.Audit.SigningKeyFile = filepath.Join(root, "audit-signing-key.pem")
	cfg.Secrets.KEKFile = filepath.Join(root, "deployment-kek")
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
	socketDir, err := os.MkdirTemp("", "tk-hsm-")
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
	log, err := openHistoryAwareEventLog(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: filepath.Join(t.TempDir(), "nats")}, st, auditKey)
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

	unlisted := servedTenantSealRequest(t, srv, token, http.MethodPost, "/api/v1/platform/tenant-key-domain/migrate",
		"tenant-migrate-unlisted", []byte(`{"wrapper_kind":"pkcs11","wrapper_id":"hsm-unlisted"}`))
	if unlisted.Code != http.StatusServiceUnavailable {
		t.Fatalf("migrate to a pkcs11 wrapper the control plane does not list = %d body=%s", unlisted.Code, unlisted.Body.String())
	}
	migrate := servedTenantSealRequest(t, srv, token, http.MethodPost, "/api/v1/platform/tenant-key-domain/migrate",
		"tenant-migrate-hsm", []byte(`{"wrapper_kind":"pkcs11","wrapper_id":"hsm-a"}`))
	if migrate.Code != http.StatusOK || !strings.Contains(migrate.Body.String(), `"remote_wrapper_state":"signer_hsm"`) ||
		!strings.Contains(migrate.Body.String(), `"local_wrapper_zero_egress":false`) {
		t.Fatalf("migrate to the signer's HSM wrapper = %d body=%s", migrate.Code, migrate.Body.String())
	}
	domain, err := deps.TenantKeyDomains.Status(ctx, hsmTenant)
	if err != nil || domain.WrapperKind != tenantseal.WrapperKindPKCS11 || !bytes.HasPrefix(domain.WrappedDomainKEK, []byte("TDH1")) {
		t.Fatalf("persisted domain = %+v, %v; want an HSM-wrapped domain KEK", domain, err)
	}
	if creates, _, _, _ := custody.calls(); creates != 1 {
		t.Fatalf("the signer created %d domain KEKs, want 1", creates)
	}

	_, _, wrapsBefore, unwrapsBefore := custody.calls()
	created := servedTenantSealRequest(t, srv, token, http.MethodPost, "/api/v1/owners", "tenant-hsm-owner",
		[]byte(`{"kind":"workload","name":"hsm-protected-owner"}`))
	if created.Code != http.StatusCreated {
		t.Fatalf("create an owner under the HSM-held domain = %d body=%s", created.Code, created.Body.String())
	}
	replayed := servedTenantSealRequest(t, srv, token, http.MethodPost, "/api/v1/owners", "tenant-hsm-owner",
		[]byte(`{"kind":"workload","name":"hsm-protected-owner"}`))
	if replayed.Code != http.StatusCreated || !bytes.Equal(replayed.Body.Bytes(), created.Body.Bytes()) {
		t.Fatalf("idempotent replay through the sealed result = %d body=%s", replayed.Code, replayed.Body.String())
	}
	if _, _, wraps, unwraps := custody.calls(); wraps <= wrapsBefore || unwraps <= unwrapsBefore {
		t.Fatalf("tenant data keys did not go through the signer: wraps %d→%d unwraps %d→%d", wrapsBefore, wraps, unwrapsBefore, unwraps)
	}

	queued := servedTenantSealRequest(t, srv, token, http.MethodPost, "/api/v1/platform/tenant-key-domain/seal", "tenant-hsm-seal", nil)
	if queued.Code != http.StatusAccepted {
		t.Fatalf("queue seal = %d body=%s", queued.Code, queued.Body.String())
	}
	if n, err := srv.outbox.DispatchScoped(ctx, srv.obHandler, orchestrator.DestinationScope{IncludePrefixes: []string{store.TenantKeyDomainSealDestination}}); err != nil || n != 1 {
		t.Fatalf("dispatch seal = %d/%v, want 1/nil", n, err)
	}
	if locked := servedTenantSealRequest(t, srv, token, http.MethodGet, "/api/v1/owners", "", nil); locked.Code != http.StatusLocked {
		t.Fatalf("sealed tenant read = %d body=%s", locked.Code, locked.Body.String())
	}
	_, opensBefore, _, _ := custody.calls()
	if unseal := servedTenantSealRequest(t, srv, token, http.MethodPost, "/api/v1/platform/tenant-key-domain/unseal", "tenant-hsm-unseal", nil); unseal.Code != http.StatusOK {
		t.Fatalf("unseal = %d body=%s", unseal.Code, unseal.Body.String())
	}
	if _, opens, _, _ := custody.calls(); opens <= opensBefore {
		t.Fatal("unseal did not prove the domain KEK opens in the signer")
	}
	if owners := servedTenantSealRequest(t, srv, token, http.MethodGet, "/api/v1/owners", "", nil); owners.Code != http.StatusOK || !strings.Contains(owners.Body.String(), "hsm-protected-owner") {
		t.Fatalf("unsealed tenant read = %d body=%s", owners.Code, owners.Body.String())
	}

	custody.mu.Lock()
	delete(custody.keys, "hsm-a")
	custody.mu.Unlock()
	failed := servedTenantSealRequest(t, srv, token, http.MethodGet, "/api/v1/owners", "", nil)
	if failed.Code == http.StatusOK || !strings.Contains(failed.Body.String(), "wrapper_unavailable") || strings.Contains(failed.Body.String(), "hsm-protected-owner") {
		t.Fatalf("a tenant whose HSM key the signer lost = %d body=%s, want a wrapper_unavailable refusal", failed.Code, failed.Body.String())
	}
}
