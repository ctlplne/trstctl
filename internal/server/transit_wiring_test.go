// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"testing"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/secrets"
	"trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/transit"
)

// TestRunConfigTransitKeyringDirReachesDeps is the wiring guard for AUD-201
// follow-up A1/V2: the sealed transit keyring shipped fully implemented but
// buildRunDeps never assigned Deps.TransitKeyringDir, so production always got
// a nil store and every transit key died with the process. This fails if that
// one assignment line is deleted again.
func TestRunConfigTransitKeyringDirReachesDeps(t *testing.T) {
	cfg := config.Default()
	cfg.RateLimit.Enabled = false
	cfg.Audit.SigningKeyFile = filepath.Join(t.TempDir(), "audit.pem")
	keyringDir := filepath.Join(t.TempDir(), "transit-keyring")
	cfg.Transit.KeyringDir = keyringDir
	auditKey := testAuditSigningKey(t)

	deps, err := buildRunDeps(context.Background(), cfg, nil, nil, runSigner{}, runSecrets{}, slog.New(slog.NewTextHandler(io.Discard, nil)), nil, auditKey)
	if err != nil {
		t.Fatalf("buildRunDeps: %v", err)
	}
	t.Cleanup(deps.Bulkhead.Close)
	if deps.TransitKeyringDir != keyringDir {
		t.Fatalf("Deps.TransitKeyringDir = %q, want %q (production wiring for transit.keyring_dir is missing)", deps.TransitKeyringDir, keyringDir)
	}
}

// TestTransitKeyringSurvivesServerRebuild is the operator-visible proof for
// A1/V2: a transit key created through one production-assembled server (real
// buildRunDeps output passed to Build, exercising buildTransitService) still
// decrypts its ciphertext after the server is torn down and rebuilt from the
// same keyring directory. Before the wiring fix this failed: nothing assigned
// TransitKeyringDir, the keyring stayed memory-only, and the second server
// could not decrypt anything from the first.
func TestTransitKeyringSurvivesServerRebuild(t *testing.T) {
	ctx := context.Background()
	persistentRoot := t.TempDir()
	keyringDir := filepath.Join(persistentRoot, "transit-keyring")

	cfg := config.Default()
	cfg.RateLimit.Enabled = false
	cfg.Audit.SigningKeyFile = filepath.Join(persistentRoot, "audit-signing-key.pem")
	cfg.Secrets.KEKFile = filepath.Join(persistentRoot, "secrets-kek")
	cfg.Secrets.AuthSecretFile = filepath.Join(persistentRoot, "machine-auth.bin")
	cfg.Secrets.AuthTokenTenantID = "11111111-1111-1111-1111-111111111111"
	cfg.Secrets.AuthTokenScopes = []string{"secrets:read"}
	cfg.Signer.AuthSecretFile = filepath.Join(persistentRoot, "sign-auth.bin")
	cfg.Signer.KeyStoreDir = filepath.Join(persistentRoot, "signer-keys")
	cfg.CA.CertFile = filepath.Join(persistentRoot, "issuing-ca.crt")
	cfg.Transit.KeyringDir = keyringDir

	plaintext := []byte("survives the restart")
	var ciphertext string
	// The shared keyring is a database row and the test database outlives one
	// test, so each run seals its own fresh tenant's row (A125).
	tenantID := uuid.NewString()

	// First life: assemble the production server, mint a key, encrypt.
	// Server.Shutdown closes the store and event log it was built with, which is
	// exactly what a process exit does — each life gets its own connections.
	{
		st := newServerTestStore(t)
		if err := st.UpsertTenant(ctx, store.Tenant{TenantID: tenantID, Name: "transit tenant", EventSeq: 1}); err != nil {
			t.Fatalf("seed tenant: %v", err)
		}
		srv := buildTransitTestServer(t, ctx, cfg, st, filepath.Join(t.TempDir(), "nats-1"))
		if !srv.transitShared {
			t.Fatal("production-assembled server keeps its transit keyring to itself instead of the shared keyring")
		}
		if _, err := srv.transit.CreateKey(ctx, tenantID, "app-key", transit.KindAEAD); err != nil {
			t.Fatalf("create transit key: %v", err)
		}
		ct, err := srv.transit.Encrypt(ctx, tenantID, "app-key", plaintext, nil)
		if err != nil {
			t.Fatalf("encrypt: %v", err)
		}
		ciphertext = ct
		if err := srv.Shutdown(ctx); err != nil {
			t.Fatalf("shutdown first server: %v", err)
		}
	}

	// Second life: rebuild from the same keyring directory and decrypt the
	// ORIGINAL ciphertext.
	{
		st, err := store.Open(ctx, serverTestPostgresDSN(t))
		if err != nil {
			t.Fatalf("reopen store for second life: %v", err)
		}
		t.Cleanup(st.Close)
		srv := buildTransitTestServer(t, ctx, cfg, st, filepath.Join(t.TempDir(), "nats-2"))
		defer func() { _ = srv.Shutdown(context.Background()) }()
		posture := srv.transitRuntimePosture(false, "", tenantID)
		if !posture.Served || !posture.PersistenceConfigured || !posture.Shared {
			t.Fatalf("restored Transit runtime posture = %+v, want a served shared keyring", posture)
		}
		kind, versions, err := srv.transit.ListKeyVersions(ctx, tenantID, "app-key")
		if err != nil || kind != transit.KindAEAD || len(versions) != 1 || !versions[0].Current {
			t.Fatalf("restored key-version history kind=%q versions=%+v err=%v", kind, versions, err)
		}
		got, err := srv.transit.Decrypt(ctx, tenantID, "app-key", ciphertext, nil)
		if err != nil {
			t.Fatalf("decrypt after rebuild: %v (the keyring did not survive the restart)", err)
		}
		if !bytes.Equal(got, plaintext) {
			t.Fatalf("decrypt after rebuild = %q, want %q", got, plaintext)
		}
	}
}

// buildTransitTestServer assembles a server the exact way production Run does:
// loadRunSecrets + buildRunDeps + Build. Nothing is stubbed between the config
// and the transit service, so the test fails if any link in the wiring chain
// (config -> Deps -> buildTransitService) is broken. The returned server owns
// the event log and store; Server.Shutdown closes both.
func buildTransitTestServer(t *testing.T, ctx context.Context, cfg *config.Config, st *store.Store, natsDir string) *Server {
	t.Helper()
	auditKey, err := jose.GenerateRSASigningKey("audit-export")
	if err != nil {
		t.Fatalf("generate audit key: %v", err)
	}
	log, err := openHistoryAwareEventLog(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: natsDir}, st, auditKey)
	if err != nil {
		t.Fatalf("open embedded event log: %v", err)
	}
	guard, err := egressGuardFromConfig(cfg.AirGap)
	if err != nil {
		_ = log.Close()
		t.Fatalf("build egress guard: %v", err)
	}
	secrets, err := loadRunSecrets(cfg)
	if err != nil {
		_ = log.Close()
		t.Fatalf("load run secrets: %v", err)
	}
	t.Cleanup(secrets.Close)
	deps, err := buildRunDeps(ctx, cfg, st, log, runSigner{}, secrets, slog.New(slog.NewTextHandler(io.Discard, nil)), guard, auditKey)
	if err != nil {
		_ = log.Close()
		t.Fatalf("production buildRunDeps: %v", err)
	}
	srv, err := Build(ctx, deps)
	if err != nil {
		_ = log.Close()
		t.Fatalf("Build from production-assembled Deps: %v", err)
	}
	return srv
}

// transitTestConfig is the production configuration the transit wiring tests
// assemble servers from, rooted at one persistent directory.
func transitTestConfig(t *testing.T, root string) *config.Config {
	t.Helper()
	cfg := config.Default()
	cfg.RateLimit.Enabled = false
	cfg.Audit.SigningKeyFile = filepath.Join(root, "audit-signing-key.pem")
	cfg.Secrets.KEKFile = filepath.Join(root, "secrets-kek")
	cfg.Secrets.AuthSecretFile = filepath.Join(root, "machine-auth.bin")
	cfg.Secrets.AuthTokenTenantID = "11111111-1111-1111-1111-111111111111"
	cfg.Secrets.AuthTokenScopes = []string{"secrets:read"}
	cfg.Signer.AuthSecretFile = filepath.Join(root, "sign-auth.bin")
	cfg.Signer.KeyStoreDir = filepath.Join(root, "signer-keys")
	cfg.CA.CertFile = filepath.Join(root, "issuing-ca.crt")
	return cfg
}

// A125: two production-assembled servers over one database are two replicas.
// A key created on one encrypts there and decrypts on the other; a rotation on
// the other produces a version the first decrypts.
func TestTransitKeysAreSharedByTwoServers(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.NewString()
	cfg := transitTestConfig(t, t.TempDir())
	st1 := newServerTestStore(t)
	if err := st1.UpsertTenant(ctx, store.Tenant{TenantID: tenantID, Name: "transit tenant", EventSeq: 1}); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	st2, err := store.Open(ctx, serverTestPostgresDSN(t))
	if err != nil {
		t.Fatalf("open the second replica's store: %v", err)
	}
	t.Cleanup(st2.Close)
	one := buildTransitTestServer(t, ctx, cfg, st1, filepath.Join(t.TempDir(), "nats-1"))
	defer func() { _ = one.Shutdown(context.Background()) }()
	two := buildTransitTestServer(t, ctx, cfg, st2, filepath.Join(t.TempDir(), "nats-2"))
	defer func() { _ = two.Shutdown(context.Background()) }()

	if _, err := one.transit.CreateKey(ctx, tenantID, "shared-key", transit.KindAEAD); err != nil {
		t.Fatalf("create on the first replica: %v", err)
	}
	v1, err := one.transit.Encrypt(ctx, tenantID, "shared-key", []byte("from one"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := two.transit.Decrypt(ctx, tenantID, "shared-key", v1, nil); err != nil || string(got) != "from one" {
		t.Fatalf("decrypt on the second replica = %q, %v", got, err)
	}
	if _, err := two.transit.Rotate(ctx, tenantID, "shared-key"); err != nil {
		t.Fatalf("rotate on the second replica: %v", err)
	}
	v2, err := two.transit.Encrypt(ctx, tenantID, "shared-key", []byte("from two"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := one.transit.Decrypt(ctx, tenantID, "shared-key", v2, nil); err != nil || string(got) != "from two" {
		t.Fatalf("decrypt of the rotated version on the first replica = %q, %v", got, err)
	}
}

// A125: a keyring file a previous version checkpointed is imported into the
// shared keyring when the server starts, so its ciphertext still decrypts, and
// the file stays where it was.
func TestTransitKeyringFileIsImportedIntoTheSharedKeyring(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.NewString()
	root := t.TempDir()
	cfg := transitTestConfig(t, root)
	cfg.Transit.KeyringDir = filepath.Join(root, "transit-keyring")

	kek, err := secrets.LoadOrCreateKEK(cfg.Secrets.KEKFile)
	if err != nil {
		t.Fatal(err)
	}
	file := transit.NewStore(cfg.Transit.KeyringDir, kek)
	old := transit.NewService(nil)
	old.SetPersist(func() error { return file.Save(old) })
	if _, err := old.CreateKey(ctx, tenantID, "file-key", transit.KindAEAD); err != nil {
		t.Fatal(err)
	}
	ciphertext, err := old.Encrypt(ctx, tenantID, "file-key", []byte("from the file"), nil)
	if err != nil {
		t.Fatal(err)
	}
	old.Destroy()
	kek.Destroy()

	st := newServerTestStore(t)
	if err := st.UpsertTenant(ctx, store.Tenant{TenantID: tenantID, Name: "transit tenant", EventSeq: 1}); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	srv := buildTransitTestServer(t, ctx, cfg, st, filepath.Join(t.TempDir(), "nats"))
	defer func() { _ = srv.Shutdown(context.Background()) }()
	if got, err := srv.transit.Decrypt(ctx, tenantID, "file-key", ciphertext, nil); err != nil || string(got) != "from the file" {
		t.Fatalf("decrypt of a file-era ciphertext = %q, %v", got, err)
	}
	if _, _, found, err := st.LoadTransitKeyring(ctx, tenantID); err != nil || !found {
		t.Fatalf("the imported keyring row = found %v, %v", found, err)
	}
	if found, err := file.HasState(); err != nil || !found {
		t.Fatalf("the keyring file after the import = found %v, %v; it must stay", found, err)
	}
}
