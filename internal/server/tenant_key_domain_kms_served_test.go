// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/crypto/kmswrap"
	"trstctl.com/trstctl/internal/crypto/tenantwrap"
	"trstctl.com/trstctl/internal/signing"
	"trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/tenantseal"
)

// kmsCustodyDouble is the signer's tenant KEK custody over wrapper keys a
// cloud KMS key wraps (OD-10): real kmswrap.WrapperKeys behind the real KMS
// wrap adapter path (an operator command), with the custody's own seal and
// open. Only the KMS is a stand-in.
type kmsCustodyDouble struct {
	mu   sync.Mutex
	keys map[string]*kmswrap.WrapperKey
}

type kmsWrapperDouble struct{ key *kmswrap.WrapperKey }

func (w kmsWrapperDouble) Seal(plaintext, aad []byte) ([]byte, error) {
	out, err := w.key.Seal(plaintext, aad)
	if err != nil {
		return nil, kmsDoubleError(err)
	}
	return out, nil
}

func (w kmsWrapperDouble) Open(sealed, aad []byte) ([]byte, error) {
	out, err := w.key.Open(sealed, aad)
	if err != nil {
		return nil, kmsDoubleError(err)
	}
	return out, nil
}

func kmsDoubleError(err error) error {
	if errors.Is(err, kmswrap.ErrWrapperKeySealedInvalid) {
		return tenantwrap.ErrUnwrap
	}
	return errors.Join(tenantwrap.ErrUnavailable, err)
}

func (c *kmsCustodyDouble) wrapper(id string) (tenantwrap.ExternalWrapper, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	key, ok := c.keys[id]
	if !ok {
		return nil, signing.ErrTenantKEKWrapperUnknown
	}
	return kmsWrapperDouble{key: key}, nil
}

func (c *kmsCustodyDouble) CreateDomainKEK(_ context.Context, id string, binding []byte) ([]byte, error) {
	w, err := c.wrapper(id)
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

func (c *kmsCustodyDouble) OpenDomainKEK(_ context.Context, id string, wrapped, binding []byte) error {
	w, err := c.wrapper(id)
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

func (c *kmsCustodyDouble) WrapDataKey(_ context.Context, id string, wrapped, binding, dataKey []byte) ([]byte, error) {
	w, err := c.wrapper(id)
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

func (c *kmsCustodyDouble) UnwrapDataKey(_ context.Context, id string, wrapped, binding, wrappedDataKey []byte) ([]byte, error) {
	w, err := c.wrapper(id)
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

// servedKMSAdapter is a stand-in for trstctl-kms-wrap that logs every call
// and refuses while the disabled file exists.
func servedKMSAdapter(t *testing.T, dir string) (command, logFile, disabled string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the KMS adapter stand-in is a POSIX script")
	}
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 is needed for the KMS adapter stand-in")
	}
	logFile, disabled = filepath.Join(dir, "kms.log"), filepath.Join(dir, "kms-disabled")
	command = filepath.Join(dir, "kms-wrap.py")
	body := `#!/usr/bin/env python3
import os
import sys

op, provider, key_ref = sys.argv[1:4]
data = sys.stdin.buffer.read()
with open("` + logFile + `", "a") as log:
    log.write(op + "\n")
if os.path.exists("` + disabled + `"):
    sys.stderr.write("KMS key disabled")
    sys.exit(5)
if op == "wrap":
    sys.stdout.buffer.write(b"kmswrap:" + data[::-1])
elif op == "unwrap" and data.startswith(b"kmswrap:"):
    sys.stdout.buffer.write(data[len(b"kmswrap:"):][::-1])
else:
    sys.exit(4)
`
	if err := os.WriteFile(command, []byte(body), 0o700); err != nil { // #nosec G306 -- fixture script in a test tempdir; the mode is part of the fixture (CWE-276)
		t.Fatal(err)
	}
	return command, logFile, disabled
}

func servedKMSUnwraps(t *testing.T, logFile string) int {
	t.Helper()
	raw, err := os.ReadFile(logFile) // #nosec G304 -- the fixture adapter's log in the test tempdir (CWE-22)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	return strings.Count(string(raw), "unwrap\n")
}

// OD-10 (A200-L4) through the default-binary composition: a tenant migrates to
// a kms wrapper the signer keeps under a cloud KMS key. The database keeps only
// the wrapped domain KEK and the control plane reports signer_kms. With the
// wrapper's cache off, every tenant data-key operation reaches the KMS through
// the adapter; after a rotation onto a wrapper with a cache time limit, the
// signer reaches it once for all of them. When the signer's custody shuts down
// (the held key wiped) or the KMS key is disabled, the tenant fails closed as
// wrapper_unavailable instead of falling back to the deployment KEK.
func TestServedTenantKeyDomainLivesInTheSignerUnderACloudKMSKeyOD10(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	command, logFile, disabled := servedKMSAdapter(t, root)
	st := newServerTestStore(t)
	const kmsTenant = "66666666-6666-4666-8666-666666666666"
	if err := st.UpsertTenant(ctx, store.Tenant{TenantID: kmsTenant, Name: "tenant-kms-served", EventSeq: 1}); err != nil {
		t.Fatal(err)
	}
	token := seedScopedToken(t, st, kmsTenant, "keys:read", "keys:write", "owners:read", "owners:write")

	cfg := config.Default()
	cfg.RateLimit.Enabled = false
	cfg.Audit.SigningKeyFile = filepath.Join(root, "audit-signing-key.pem")
	cfg.Secrets.KEKFile = filepath.Join(root, "deployment-kek")
	cfg.Signer.AuthSecretFile = filepath.Join(root, "sign-auth.bin")
	cfg.Signer.KeyStoreDir = filepath.Join(root, "signer-keys")
	cfg.CA.CertFile = filepath.Join(root, "issuing-ca.crt")
	cfg.Secrets.TenantSealKMSWrappers = []config.TenantSealKMSWrapper{{ID: "kms-uncached"}, {ID: "kms-cached"}}

	adapter, err := kmswrap.NewExternalKMSWrapper(kmswrap.ExternalKMSConfig{Provider: "awskms",
		KeyRef: "arn:aws:kms:us-east-1:111122223333:key/tenant-kek", WrapCommand: command, Timeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	newKey := func(cache time.Duration) (*kmswrap.WrapperKey, []byte) {
		t.Helper()
		wrapped, err := kmswrap.CreateWrapperKey(adapter)
		if err != nil {
			t.Fatal(err)
		}
		key, err := kmswrap.NewWrapperKey(adapter, wrapped, cache)
		if err != nil {
			t.Fatal(err)
		}
		return key, wrapped
	}
	uncached, _ := newKey(0)
	cached, cachedWrapped := newKey(10 * time.Minute)
	custody := &kmsCustodyDouble{keys: map[string]*kmswrap.WrapperKey{"kms-uncached": uncached, "kms-cached": cached}}
	t.Cleanup(func() { uncached.Close(); cached.Close() })

	authz, err := signing.LoadOrCreateAuthorizer(filepath.Join(root, "signer-auth.bin"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(authz.Destroy)
	socketDir, err := os.MkdirTemp("", "tk-kms-")
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

	// A kms wrapper the control plane does not list is not configured; a
	// pkcs11 kind under a kms wrapper's ID does not match it either.
	for name, body := range map[string]string{
		"an unlisted kms wrapper":       `{"wrapper_kind":"kms","wrapper_id":"kms-unlisted"}`,
		"the kms ID under another kind": `{"wrapper_kind":"pkcs11","wrapper_id":"kms-uncached"}`,
	} {
		if refused := servedTenantSealRequest(t, srv, token, http.MethodPost, "/api/v1/platform/tenant-key-domain/migrate",
			"tenant-migrate-"+strings.ReplaceAll(name, " ", "-"), []byte(body)); refused.Code != http.StatusServiceUnavailable {
			t.Fatalf("migrate to %s = %d body=%s", name, refused.Code, refused.Body.String())
		}
	}
	migrate := servedTenantSealRequest(t, srv, token, http.MethodPost, "/api/v1/platform/tenant-key-domain/migrate",
		"tenant-migrate-kms", []byte(`{"wrapper_kind":"kms","wrapper_id":"kms-uncached"}`))
	if migrate.Code != http.StatusOK || !strings.Contains(migrate.Body.String(), `"remote_wrapper_state":"signer_kms"`) ||
		!strings.Contains(migrate.Body.String(), `"local_wrapper_zero_egress":false`) {
		t.Fatalf("migrate to the signer's kms wrapper = %d body=%s", migrate.Code, migrate.Body.String())
	}
	domain, err := deps.TenantKeyDomains.Status(ctx, kmsTenant)
	if err != nil || domain.WrapperKind != tenantseal.WrapperKindKMS || !bytes.HasPrefix(domain.WrappedDomainKEK, []byte("TDH1")) {
		t.Fatalf("persisted domain = %+v, %v; want a domain KEK the kms wrapper wraps", domain, err)
	}

	// Cache off: every data-key operation reaches the KMS.
	before := servedKMSUnwraps(t, logFile)
	for _, name := range []string{"kms-owner-a", "kms-owner-b"} {
		if created := servedTenantSealRequest(t, srv, token, http.MethodPost, "/api/v1/owners", name,
			[]byte(`{"kind":"workload","name":"`+name+`"}`)); created.Code != http.StatusCreated {
			t.Fatalf("create %s under the kms wrapper = %d body=%s", name, created.Code, created.Body.String())
		}
	}
	uncachedCalls := servedKMSUnwraps(t, logFile) - before
	if uncachedCalls < 2 || uncached.Unwraps() < 2 || uncached.Cached() {
		t.Fatalf("cache off: two owners made %d KMS unwraps (key unwraps %d, held %v); want one per data-key operation", uncachedCalls, uncached.Unwraps(), uncached.Cached())
	}

	// Rotate onto the cached wrapper: one KMS call, however many operations.
	rotate := servedTenantSealRequest(t, srv, token, http.MethodPost, "/api/v1/platform/tenant-key-domain/rotate",
		"tenant-kms-rotate", []byte(`{"wrapper_kind":"kms","wrapper_id":"kms-cached"}`))
	if rotate.Code != http.StatusOK || !strings.Contains(rotate.Body.String(), `"wrapper_id":"kms-cached"`) {
		t.Fatalf("rotate onto the cached kms wrapper = %d body=%s", rotate.Code, rotate.Body.String())
	}
	if cached.Unwraps() != 1 || !cached.Cached() {
		t.Fatalf("the rotation unwrapped the cached wrapper key %d times (held %v), want once", cached.Unwraps(), cached.Cached())
	}
	before = servedKMSUnwraps(t, logFile)
	for _, name := range []string{"kms-owner-c", "kms-owner-d", "kms-owner-e"} {
		if created := servedTenantSealRequest(t, srv, token, http.MethodPost, "/api/v1/owners", name,
			[]byte(`{"kind":"workload","name":"`+name+`"}`)); created.Code != http.StatusCreated {
			t.Fatalf("create %s under the cached kms wrapper = %d body=%s", name, created.Code, created.Body.String())
		}
	}
	if owners := servedTenantSealRequest(t, srv, token, http.MethodGet, "/api/v1/owners", "", nil); owners.Code != http.StatusOK || !strings.Contains(owners.Body.String(), "kms-owner-e") {
		t.Fatalf("read owners under the cached kms wrapper = %d body=%s", owners.Code, owners.Body.String())
	}
	if after := servedKMSUnwraps(t, logFile); after != before || cached.Unwraps() != 1 {
		t.Fatalf("cache on: three owners and a read made %d more KMS unwraps (key unwraps %d); want none", after-before, cached.Unwraps())
	}

	// The signer's shutdown wipes the held key: the tenant fails closed.
	cached.Close()
	failed := servedTenantSealRequest(t, srv, token, http.MethodGet, "/api/v1/owners", "", nil)
	if failed.Code == http.StatusOK || !strings.Contains(failed.Body.String(), "wrapper_unavailable") || strings.Contains(failed.Body.String(), "kms-owner") {
		t.Fatalf("a tenant whose wrapper key the signer wiped = %d body=%s, want a wrapper_unavailable refusal", failed.Code, failed.Body.String())
	}
	if after := servedKMSUnwraps(t, logFile); after != before {
		t.Fatal("a closed wrapper key reached the KMS")
	}

	// The signer restarts with the same wrapped key and the cache off: the
	// tenant reads again, reaching the KMS; once the KMS key is disabled, it
	// fails closed.
	restarted, err := kmswrap.NewWrapperKey(adapter, cachedWrapped, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(restarted.Close)
	custody.mu.Lock()
	custody.keys["kms-cached"] = restarted
	custody.mu.Unlock()
	if owners := servedTenantSealRequest(t, srv, token, http.MethodGet, "/api/v1/owners", "", nil); owners.Code != http.StatusOK || !strings.Contains(owners.Body.String(), "kms-owner-e") {
		t.Fatalf("read owners after the signer restart = %d body=%s", owners.Code, owners.Body.String())
	}
	if restarted.Unwraps() == 0 {
		t.Fatal("the restarted signer read the tenant without reaching the KMS")
	}
	if err := os.WriteFile(disabled, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if failed := servedTenantSealRequest(t, srv, token, http.MethodGet, "/api/v1/owners", "", nil); failed.Code == http.StatusOK ||
		!strings.Contains(failed.Body.String(), "wrapper_unavailable") {
		t.Fatalf("a tenant whose KMS key is disabled = %d body=%s, want a wrapper_unavailable refusal", failed.Code, failed.Body.String())
	}
}
