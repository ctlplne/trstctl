// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/store"
)

// A running projection can hold the tenant's event-protection lock just as a
// separate local bootstrap command starts. The command must wait before it
// generates the raw token, then emit exactly one token event after the lock is
// released. Retrying a mutation after an ambiguous event-append failure would
// be unsafe because the first raw token cannot be recovered.
func TestBootstrapTokenWaitsForTenantEventProtectionBeforeMint(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	dsn := serverTestPostgresDSN(t)
	st, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	resetServerTestStore(t, st)

	cfg := config.Default()
	cfg.Postgres = config.Postgres{Mode: config.PostgresExternal, DSN: dsn}
	cfg.NATS = config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()}
	cfg.Audit.SigningKeyFile = filepath.Join(t.TempDir(), "audit-signing-key.pem")
	cfg.Secrets.KEKFile = filepath.Join(t.TempDir(), "credential-kek.bin")
	configureExternalAuditTestSigner(t, cfg)
	const tenant = "11111111-1111-4111-8111-111111111111"
	first, err := RunTokenCreate(ctx, cfg, TokenCreateOptions{TenantID: tenant, TenantName: "contention", Subject: "first"})
	if err != nil {
		t.Fatalf("initial tenant bootstrap: %v", err)
	}
	secret.Wipe(first)

	entered := make(chan struct{})
	release := make(chan struct{})
	lockDone := make(chan error, 1)
	go func() {
		lockDone <- st.WithTenantEventProtection(ctx, tenant, func(context.Context) error {
			close(entered)
			<-release
			return nil
		})
	}()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	// The separate bootstrap process begins while the event lock is genuinely
	// held, then the projection releases it inside the bounded retry window.
	go func() {
		time.Sleep(750 * time.Millisecond)
		close(release)
	}()
	raw, err := RunTokenCreate(ctx, cfg, TokenCreateOptions{TenantID: tenant, TenantName: "contention", Subject: "after-wait"})
	defer secret.Wipe(raw)
	if err != nil {
		t.Fatalf("token create during finite tenant-lock contention: %v", err)
	}
	if !bytes.HasPrefix(raw, []byte("trst_")) {
		t.Fatal("bootstrap returned no usable token after contention")
	}
	if err := <-lockDone; err != nil {
		t.Fatalf("held tenant event protection: %v", err)
	}
	var count int
	if err := st.SystemPool().QueryRow(ctx,
		`SELECT count(*) FROM api_tokens WHERE tenant_id = $1 AND subject = $2`, tenant, "after-wait").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("contended bootstrap recorded %d after-wait tokens, want one", count)
	}
}
