// SPDX-License-Identifier: MPL-2.0

package server

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/jose"
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

	// First life: assemble the production server, mint a key, encrypt.
	// Server.Shutdown closes the store and event log it was built with, which is
	// exactly what a process exit does — each life gets its own connections.
	{
		st := newServerTestStore(t)
		if err := st.UpsertTenant(ctx, store.Tenant{TenantID: servedTestTenant, Name: "transit tenant", EventSeq: 1}); err != nil {
			t.Fatalf("seed tenant: %v", err)
		}
		srv := buildTransitTestServer(t, ctx, cfg, st, filepath.Join(t.TempDir(), "nats-1"))
		if srv.transitStore == nil {
			t.Fatal("production-assembled server built no transit store despite a configured keyring dir")
		}
		if _, err := srv.transit.CreateKey(ctx, servedTestTenant, "app-key", transit.KindAEAD); err != nil {
			t.Fatalf("create transit key: %v", err)
		}
		ct, err := srv.transit.Encrypt(ctx, servedTestTenant, "app-key", plaintext, nil)
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
		got, err := srv.transit.Decrypt(ctx, servedTestTenant, "app-key", ciphertext, nil)
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
