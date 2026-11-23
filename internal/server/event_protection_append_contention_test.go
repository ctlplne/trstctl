// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/eventprotect"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

type unusedAdmissionKeys struct{}

type legacyStoreAdmission struct{ *store.Store }

func (legacyStoreAdmission) EventProtectionFor(context.Context, events.Event) (events.EventProtectionDecision, error) {
	return events.EventProtectionDecision{Mode: events.EventProtectionLegacy}, nil
}

func (unusedAdmissionKeys) WithKey(context.Context, eventprotect.KeyRef, func(seal.KeyWrapper) error) error {
	return errors.New("unexpected protected-key use in legacy tenant test")
}

// The live PostgreSQL fence can briefly belong to a projector when a KMIP
// mutation or another event producer attempts its immutable append. Admission
// should wait before executing the publication callback and append only once.
func TestProtectedEventAppendWaitsForTenantAdmissionBeforePublication(t *testing.T) {
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
	const tenant = "11111111-1111-4111-8111-111111111111"
	cfg := config.Default()
	cfg.Postgres = config.Postgres{Mode: config.PostgresExternal, DSN: dsn}
	cfg.NATS = config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()}
	cfg.Audit.SigningKeyFile = filepath.Join(t.TempDir(), "audit-signing-key.pem")
	cfg.Secrets.KEKFile = filepath.Join(t.TempDir(), "credential-kek.bin")
	configureExternalAuditTestSigner(t, cfg)
	token, err := RunTokenCreate(ctx, cfg, TokenCreateOptions{TenantID: tenant, TenantName: "contention", Subject: "setup"})
	if err != nil {
		t.Fatal(err)
	}
	secret.Wipe(token)

	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()},
		events.WithEventProtection(events.EventProtection{Admission: legacyStoreAdmission{st}, Keys: unusedAdmissionKeys{}}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
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
	go func() {
		time.Sleep(750 * time.Millisecond)
		close(release)
	}()
	const eventID = "c746af0e-a742-450a-ad84-88cad970d306"
	if _, err := log.Append(ctx, events.Event{ID: eventID, TenantID: tenant, Type: "test.event.admission", Data: []byte(`{}`)}); err != nil {
		t.Fatalf("append after finite tenant admission contention: %v", err)
	}
	if err := <-lockDone; err != nil {
		t.Fatal(err)
	}
	count := 0
	if err := log.Replay(ctx, 0, func(ev events.Event) error {
		if ev.ID == eventID {
			count++
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("contended event was appended %d times, want once", count)
	}
}
