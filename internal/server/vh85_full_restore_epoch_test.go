// SPDX-License-Identifier: BUSL-1.1

package server

// VH85 (R1 verify of lead V2ND-124-N1): the operator full restore (RunFullBackup ->
// RunFullRestore into a fresh PostgreSQL + fresh NATS target) of an ordinary
// application-secret history with NO key rotation and NO rewrap:
// create v1 -> real queueSecretSyncEvent -> rotate v2.

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/secrets"
	"trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/storetest"
	"trstctl.com/trstctl/internal/tenantseal"
)

type vh85SeedFunc func(t *testing.T, cfg *config.Config, st *store.Store, log *events.Log,
	auditKey *jose.SigningKey, tenant string, opts []projections.Option)

var vh85PrepareHook func(*testing.T, *config.Config)
var vh85SourceStoreHook func(*testing.T, *store.Store, string) *store.Store
var vh85SeedHook vh85SeedFunc

func vh85Hex(ch byte) string { return strings.Repeat(string(ch), 64) }

func vh85Seed(syncFirst bool) vh85SeedFunc {
	return vh85SeedVariant(syncFirst, false)
}

func vh85SeedVariant(syncFirst, embedded bool) vh85SeedFunc {
	return func(t *testing.T, cfg *config.Config, st *store.Store, log *events.Log, _ *jose.SigningKey, tenant string, opts []projections.Option) {
		t.Helper()
		ctx := context.Background()
		kek, err := secrets.LoadOrCreateKEK(cfg.Secrets.KEKFile)
		if err != nil {
			t.Fatal(err)
		}
		defer kek.Destroy()
		epoch, err := st.ApplicationSecretTenantEpoch(ctx, tenant) // the live path: random epoch, no event
		if err != nil {
			t.Fatal(err)
		}
		const name = "vh85/db/password"
		aad := []byte(tenant + "/secret-store/" + name)
		project := func(label string) {
			if err := projections.New(st, opts...).ProjectCatchUp(ctx, log); err != nil {
				t.Fatalf("source catch-up after %s: %v", label, err)
			}
		}
		mutate := func(id, typ string, m projections.ApplicationSecretMutation, seed byte, value string) {
			sealed, err := sealTenantValue(ctx, nil, kek, tenant, []byte(value), aad)
			if err != nil {
				t.Fatal(err)
			}
			m.Sealed, m.TenantEpoch, m.Name, m.Surface = sealed, epoch, name, "native"
			if embedded && m.Action == "rotate" {
				jobID := store.DurableSecretSyncJobIDForEpoch(tenant, epoch, "vh85-embedded-1")
				syncValue := []byte("vh85-embedded-value")
				syncSealed, sealErr := sealTenantValue(ctx, nil, kek, tenant, syncValue,
					secretSyncAAD(tenant, "ci", jobID, "VH85_REMOTE"))
				if sealErr != nil {
					t.Fatal(sealErr)
				}
				m.Sync = &projections.SecretSyncQueued{
					TenantEpoch: epoch, ID: jobID, SecretName: name, SecretVersion: 2,
					Target: "ci", RemoteKey: "VH85_REMOTE", ValueDigest: crypto.SHA256Hex(syncValue),
					IdempotencyKey: store.SecretSyncOutboxIdempotencyKey("ci", jobID),
					RequestBinding: vh85Hex('b'), Sealed: syncSealed,
				}
			}
			m.IdempotencyKeyDigest, m.RequestBinding, m.CommandEvidence = vh85Hex(seed), vh85Hex(seed+1), vh85Hex(seed+2)
			if m.Sync != nil {
				m.Surface = "rotation"
				m.Sync.RequestBinding = m.RequestBinding
			}
			payload, err := json.Marshal(m)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := log.Append(ctx, events.Event{ID: id, Type: typ, TenantID: tenant, Time: time.Now().UTC(),
				SchemaVersion: projections.ApplicationSecretMutationSchemaVersion, Data: payload}); err != nil {
				t.Fatal(err)
			}
			project(m.Action)
		}
		queue := func(secretName string) { // the production standalone secret-sync emitter
			if err := queueSecretSyncEvent(ctx, st, log, kek, tenant, secretName, 1, "ci", "VH85_REMOTE",
				"vh85-sync-1", vh85Hex('b'), []byte("vh85-sync-value"), nil); err != nil {
				t.Fatalf("queue secret sync: %v", err)
			}
			project("sync queued")
		}
		if syncFirst {
			queue("vh85/other")
		}
		mutate("a8850000-0000-4000-8000-0000000085e1", projections.EventApplicationSecretCreated,
			projections.ApplicationSecretMutation{Action: "create", ResultVersion: 1}, '1', "vh85-value-one")
		if !syncFirst && !embedded {
			queue(name)
		}
		mutate("a8850000-0000-4000-8000-0000000085e2", projections.EventApplicationSecretRotated,
			projections.ApplicationSecretMutation{Action: "rotate", ExpectedVersion: 1, ResultVersion: 2}, '4', "vh85-value-two")
		var versions int
		_ = st.SystemPool().QueryRow(ctx, `SELECT count(*) FROM secret_store_versions WHERE tenant_id = $1`, tenant).Scan(&versions)
		t.Logf("source (live projection accepted the history): secret_store_versions=%d syncFirst=%v", versions, syncFirst)
	}
}

func TestVH85FullRestoreEmbeddedSyncBeforeRotate(t *testing.T) {
	vh85SeedHook = vh85SeedVariant(false, true)
	t.Cleanup(func() { vh85SeedHook = nil })
	info := eventProtectionPostgresBackupFixture(t, time.Hour, false)
	target := protectedSQLRestoreTarget(t, info.Config)
	if _, err := RunFullRestore(t.Context(), target, info.Directory); err != nil {
		t.Fatalf("VH85 embedded sync full restore: %v", err)
	}
}

func vh85RunFullRestore(t *testing.T, syncFirst bool) error {
	vh85SeedHook = vh85Seed(syncFirst)
	t.Cleanup(func() { vh85SeedHook = nil })
	info := eventProtectionPostgresBackupFixture(t, time.Hour, false)
	target := protectedSQLRestoreTarget(t, info.Config)
	_, err := RunFullRestore(t.Context(), target, info.Directory)
	t.Logf("RunFullRestore into a fresh target (syncFirst=%v): err=%v", syncFirst, err)
	return err
}

func TestVH85FullRestoreCreateBeforeFirstSync(t *testing.T) {
	if err := vh85RunFullRestore(t, false); err != nil {
		t.Fatalf("VH85: --full-restore-dir restore of create -> sync -> rotate (no rewrap) failed: %v", err)
	}
}

func TestVH85FullRestoreControlSyncBeforeCreate(t *testing.T) {
	if err := vh85RunFullRestore(t, true); err != nil {
		t.Fatalf("VH85 control: sync -> create -> rotate restore failed: %v", err)
	}
}

// CR-045: full restore must reconstruct a source whose secret and retained
// sync command were rewrapped after their events were first projected.
func TestVH85FullRestoreAfterTenantDomainRewrapCR045(t *testing.T) {
	runVH85FullRestoreAfterTenantDomainRewrapCR045(t, false)
}

func TestVH85FullRestoreAfterTenantDomainRewrapEmbeddedSyncCR045(t *testing.T) {
	runVH85FullRestoreAfterTenantDomainRewrapCR045(t, true)
}

func runVH85FullRestoreAfterTenantDomainRewrapCR045(t *testing.T, embedded bool) {
	const wrapperID = "vh85-restore-wrapper"
	var wrapperPath string
	vh85PrepareHook = func(t *testing.T, cfg *config.Config) {
		wrapperPath = filepath.Join(t.TempDir(), "tenant-wrapper.key")
		if err := os.WriteFile(wrapperPath, bytes.Repeat([]byte{0x73}, 32), 0o600); err != nil {
			t.Fatal(err)
		}
		cfg.Secrets.TenantSealLocalWrappers = []config.TenantSealLocalWrapper{{ID: wrapperID, File: wrapperPath}}
	}
	t.Cleanup(func() { vh85PrepareHook = nil })
	vh85SourceStoreHook = func(t *testing.T, admin *store.Store, dsn string) *store.Store {
		cutover := storetest.ProvisionRewrapCutover(t, admin, dsn)
		owner, err := store.Open(t.Context(), cutover.DSN, store.WithRewrapFleetCutover(cutover.Cutover))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(owner.Close)
		return owner
	}
	t.Cleanup(func() { vh85SourceStoreHook = nil })
	vh85SeedHook = func(t *testing.T, cfg *config.Config, st *store.Store, log *events.Log,
		auditKey *jose.SigningKey, tenant string, opts []projections.Option,
	) {
		vh85SeedVariant(false, embedded)(t, cfg, st, log, auditKey, tenant, opts)
		before, err := st.GetSecret(t.Context(), tenant, "vh85/db/password")
		if err != nil {
			t.Fatal(err)
		}
		deployment, err := secrets.LoadOrCreateKEK(cfg.Secrets.KEKFile)
		if err != nil {
			t.Fatal(err)
		}
		defer deployment.Destroy()
		registry, err := tenantseal.NewLocalWrapperRegistry([]tenantseal.LocalWrapper{{ID: wrapperID, Path: wrapperPath}})
		if err != nil {
			t.Fatal(err)
		}
		lifecycle, err := tenantseal.NewLifecycle(st, log, deployment, registry,
			historyRewriteProofOptions(st, auditKey)...)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := lifecycle.Migrate(t.Context(), tenant,
			tenantseal.WrapperRef{Kind: tenantseal.WrapperKindLocalFile, ID: wrapperID}); err != nil {
			if domain, readErr := st.GetTenantKeyDomain(t.Context(), tenant); readErr == nil {
				t.Logf("migration stopped at stage=%s status=%s", domain.MigrationStage, domain.OperationStatus)
			}
			if gate, found, readErr := st.GetTenantApplicationSecretRewrapGate(t.Context(), tenant); readErr == nil && found {
				t.Logf("migration gate in_progress=%t generation=%d", gate.InProgress, gate.Generation)
			}
			t.Fatalf("migrate source tenant before full backup: %v", err)
		}
		after, err := st.GetSecret(t.Context(), tenant, "vh85/db/password")
		if err != nil || bytes.Equal(before.Sealed, after.Sealed) {
			t.Fatalf("source did not change retained sealed secret under rewrap: %v", err)
		}
	}
	t.Cleanup(func() { vh85SeedHook = nil })
	info := eventProtectionPostgresBackupFixture(t, time.Hour, false)
	target := protectedSQLRestoreTarget(t, info.Config)
	if _, err := RunFullRestore(t.Context(), target, info.Directory); err != nil {
		t.Fatalf("full restore after tenant-domain rewrap: %v", err)
	}
	restored, err := store.Open(t.Context(), target.Postgres.DSN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(restored.Close)
	if secret, err := restored.GetSecret(t.Context(), info.Tenant, "vh85/db/password"); err != nil || secret.Version != 2 {
		t.Fatalf("restored rewrapped secret version=%d err=%v", secret.Version, err)
	}
}
