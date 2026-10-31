// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/eventprivacy"
	"trstctl.com/trstctl/internal/eventprotect"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
)

func eventProtectionRuntimeConfigFixture(t *testing.T) *config.Config {
	t.Helper()
	base := t.TempDir()
	cfg := config.Default()
	cfg.NATS.StoreDir = filepath.Join(base, "events")
	cfg.Postgres.DataDir = filepath.Join(base, "postgres")
	cfg.Signer.KeyStoreDir = filepath.Join(base, "signer")
	cfg.Signer.AuthSecretFile = filepath.Join(base, "signer-auth.bin")
	cfg.CA.CertFile = filepath.Join(base, "ca.crt")
	cfg.Secrets.KEKFile = filepath.Join(base, "kek.bin")
	cfg.Audit.SigningKeyFile = filepath.Join(base, "legacy-audit.pem")
	cfg.Audit.ArchiveDir = filepath.Join(base, "archive")
	cfg.Backup.Directory = filepath.Join(base, "backups")
	cfg.Privacy.EventProtection.KeyDirectory = filepath.Join(base, "independent-keys")
	return cfg
}

func TestEventProtectionRuntimeExcludesEveryManagedBackupRoot(t *testing.T) {
	st := newServerTestStore(t)
	key := testAuditSigningKey(t)
	for _, name := range []string{"event-log", "postgres", "signer-keystore", "signer-auth-file", "audit-signing-key-file", "audit-archives", "configured-backups", "ca-certificate-file", "secrets-kek-file", "actual-backup-destination", "backup-output-inside-custody"} {
		t.Run(name, func(t *testing.T) {
			cfg := eventProtectionRuntimeConfigFixture(t)
			root := map[string]string{"event-log": cfg.NATS.StoreDir, "postgres": cfg.Postgres.DataDir, "signer-keystore": cfg.Signer.KeyStoreDir, "signer-auth-file": cfg.Signer.AuthSecretFile, "audit-signing-key-file": cfg.Audit.SigningKeyFile, "ca-certificate-file": cfg.CA.CertFile, "secrets-kek-file": cfg.Secrets.KEKFile, "audit-archives": cfg.Audit.ArchiveDir, "configured-backups": cfg.Backup.Directory, "actual-backup-destination": filepath.Join(t.TempDir(), "actual-backup")}[name]
			cfg.Privacy.EventProtection.KeyDirectory = filepath.Join(root, "event-keys")
			var extra []string
			if name == "actual-backup-destination" {
				extra = []string{root}
			}
			if name == "backup-output-inside-custody" {
				cfg.Privacy.EventProtection.KeyDirectory = filepath.Join(t.TempDir(), "custody")
				extra = []string{filepath.Join(cfg.Privacy.EventProtection.KeyDirectory, "backup.out")}
			}
			if runtime, err := newEventProtectionRuntime(cfg, st, key, extra...); err == nil {
				_ = runtime.Close()
				t.Fatal("ordinary managed backup can capture independent tenant keys")
			}
		})
	}
}

// This qualifies actual operator rebuild, constructor ordering and restart
// readback. The signer RPC runs as a test fixture in this process and activation
// is explicit; this does not qualify isolated-process custody, background
// preparation/destruction, full-backup restoration or the full operator lifecycle.
func TestEventProtectionRuntimeBindsAdmissionAndKeysBeforeOpenAndRefusesMissingCustodyOnRestart(t *testing.T) {
	st := newServerTestStore(t)
	cfg := eventProtectionRuntimeConfigFixture(t)
	cfg.Postgres.Mode = config.PostgresExternal
	cfg.Postgres.DSN = serverTestPostgresDSN(t)
	cfg.NATS.Mode = config.NATSExternal
	// The owned fixture is a single-host evaluation, never cluster proof.
	cfg.NATS.Replicas = 1
	cfg.NATS.AllowSingleReplica = true
	cfg.NATS.URL = startBackupTestNATS(t).ClientURL()
	configureExternalAuditTestSigner(t, cfg)
	signer, key, err := openAuditSigningRuntime(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(signer.Close)
	log, runtime, err := openConfiguredEventSource(t.Context(), cfg, st, key, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runtime.Close() })
	t.Cleanup(func() { _ = log.Close() })
	const tenant = "11111111-1111-1111-1111-111111111111"
	registration, err := log.Append(t.Context(), events.Event{Type: "tenant.registered", TenantID: tenant, Data: []byte(`{"name":"fixture"}`)})
	if err != nil {
		t.Fatal(err)
	}
	request, err := eventprivacy.NewRequested(tenant, registration.ID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	requested, err := log.Append(t.Context(), events.Event{ID: eventprivacy.RequestedEventID(request), Type: eventprivacy.EventRequested, TenantID: tenant, Data: wire})
	if err != nil {
		t.Fatal(err)
	}
	ref := eventprotect.KeyRef{TenantID: tenant, ID: request.KeyID}
	if err := runtime.custody.Provision(t.Context(), ref); err != nil {
		t.Fatal(err)
	}
	creation, err := runtime.custody.CreationEvidence(t.Context(), ref)
	if err != nil {
		t.Fatal(err)
	}
	activation := eventprivacy.Activated{RegistrationIdentity: registration.ID, OperationID: request.KeyID, KeyID: request.KeyID, RetentionNanos: request.RetentionNanos, RequestedEventID: requested.ID, RequestedSequence: requested.Sequence, RequestedAt: requested.Time, Creation: creation}
	wire, err = json.Marshal(activation)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := log.Append(t.Context(), events.Event{ID: request.KeyID, Type: eventprivacy.EventActivated, TenantID: tenant, Data: wire}); err != nil {
		t.Fatal(err)
	}
	wire, err = json.Marshal(projections.OwnerCreated{ID: "aaaaaaaa-0000-0000-0000-000000000001", Kind: "team", Name: "Runtime fixture", Email: "fixture-private@example.invalid"})
	if err != nil {
		t.Fatal(err)
	}
	private, err := log.Append(t.Context(), events.Event{ID: "runtime-private-fixture", Type: projections.EventOwnerCreated, TenantID: tenant, Data: wire})
	if err != nil || private.Protection == nil {
		t.Fatalf("constructor did not attach source protection: %v", err)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	missingCfg := *cfg
	missingCfg.Privacy.EventProtection.KeyDirectory = ""
	missing, err := newEventProtectionRuntime(&missingCfg, st, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = missing.Close() })
	if missing.reader == nil || missing.admission == nil || missing.custody != nil {
		t.Fatal("default-off configuration omitted the fail-closed source adapters")
	}
	without, missingOpen, err := openConfiguredEventSource(t.Context(), &missingCfg, st, key, true, nil)
	if err == nil {
		_, _, err = without.EventByID(t.Context(), private.ID)
		_ = without.Close()
		_ = missingOpen.Close()
	}
	if !errors.Is(err, eventprivacy.ErrSource) && !errors.Is(err, eventprotect.ErrKey) {
		t.Fatalf("protected restart with unavailable custody did not refuse explicitly: %v", err)
	}
	if n, err := RunRebuild(t.Context(), cfg); err != nil || n != 4 {
		t.Fatalf("operator rebuild failed to attach the configured source/custody before recovery: n=%d err=%v", n, err)
	}
	again, restored, err := openConfiguredEventSource(t.Context(), cfg, st, key, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = restored.Close() })
	t.Cleanup(func() { _ = again.Close() })
	got, found, err := again.EventByID(t.Context(), private.ID)
	if err != nil || !found || !bytes.Equal(got.Data, private.Data) {
		t.Fatalf("restored independent custody did not recover exact readable source: %v", err)
	}
	after, err := restored.custody.CreationEvidence(t.Context(), ref)
	if err != nil || after.Digest() != creation.Digest() {
		t.Fatalf("restart regenerated historical key custody: %v", err)
	}
}
