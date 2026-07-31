// SPDX-License-Identifier: MPL-2.0

package store_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/tenantseal"
)

// TestTenantKeyDomainLifecycleMigratesSealsAndUnsealsOneTenant proves the real
// PostgreSQL + embedded-JetStream path: tenant A's hot rows and event history
// move without payload plaintext, sealing A does not stop B, and neither
// tenant's resolver can use the other's protection domain.
func TestTenantKeyDomainLifecycleMigratesSealsAndUnsealsOneTenant(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	for _, tenantID := range []string{tenantA, tenantB} {
		if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenantID, Name: tenantID}); err != nil {
			t.Fatal(err)
		}
	}

	deployment := migrationTestKEK(t, 0x51)
	wrapperPath := filepath.Join(t.TempDir(), "tenant-wrapper.key")
	if err := os.WriteFile(wrapperPath, bytes.Repeat([]byte{0x52}, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	registry, err := tenantseal.NewLocalWrapperRegistry([]tenantseal.LocalWrapper{{
		ID: "tenant-a-custody", Path: wrapperPath,
	}})
	if err != nil {
		t.Fatal(err)
	}

	storeDir := t.TempDir()
	log, err := events.Open(
		ctx,
		config.NATS{Mode: config.NATSEmbedded, StoreDir: storeDir},
		events.WithHistoryRewriteCoordinator(store.NewHistoryRewriteCoordinator(s)),
		events.WithHistoryRewriteContinuityVerifier(func(
			_ context.Context,
			evidence events.TenantDataContinuityEvidence,
		) error {
			if evidence.TenantID == "" || evidence.Receipt.Type != projections.EventHistoryTenantDataRewriteContinuity {
				return errors.New("invalid tenant-domain continuity receipt")
			}
			return nil
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })

	rewriteOptions := []events.TenantDataRewriteOption{
		events.WithTenantDataCutoverPreparation(s.PrepareTenantDataCutover),
		events.WithTenantDataAuditContinuity(func(
			context.Context,
			events.TenantDataAuditView,
		) (events.TenantDataAuditCheckpoint, error) {
			return events.TenantDataAuditCheckpoint{IdentityDigest: "tenant-domain-test-genesis"}, nil
		}),
		events.WithTenantDataContinuity(func(
			_ context.Context,
			report events.TenantDataRewriteReport,
		) (events.Event, error) {
			data, err := json.Marshal(report)
			return events.Event{
				ID:       "tenant-domain-continuity-" + report.OperationID,
				Type:     projections.EventHistoryTenantDataRewriteContinuity,
				TenantID: report.TenantID, Time: report.CompletedAt,
				SchemaVersion: events.DefaultSchemaVersion, Data: data,
			}, err
		}),
	}
	lifecycle, err := tenantseal.NewLifecycle(s, log, deployment, registry, rewriteOptions...)
	if err != nil {
		t.Fatal(err)
	}

	aadA := []byte("credential:tenant-a")
	aadB := []byte("credential:tenant-b")
	legacyA, err := seal.Seal(deployment, []byte("tenant-a-secret"), aadA)
	if err != nil {
		t.Fatal(err)
	}
	legacyB, err := seal.Seal(deployment, []byte("tenant-b-secret"), aadB)
	if err != nil {
		t.Fatal(err)
	}
	for index, fixture := range []struct {
		tenantID string
		sealed   []byte
	}{
		{tenantID: tenantA, sealed: legacyA},
		{tenantID: tenantB, sealed: legacyB},
	} {
		if err := s.WithTenant(ctx, fixture.tenantID, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx,
				`INSERT INTO credentials (id, tenant_id, scope, ref, name, sealed)
				 VALUES ($1, $2, 'connector', 'target', 'token', $3)`,
				uuid(fixture.tenantID, index+90), fixture.tenantID, fixture.sealed)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		data, err := json.Marshal(map[string]any{"sealed": fixture.sealed, "tenant_marker": fixture.tenantID})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := log.Append(ctx, events.Event{
			ID:   "tenant-domain-source-" + fixture.tenantID,
			Type: "secret.version.written", TenantID: fixture.tenantID,
			Time: time.Now().UTC(), Data: data,
		}); err != nil {
			t.Fatal(err)
		}
	}

	migrated, err := lifecycle.Migrate(ctx, tenantA, tenantseal.WrapperRef{
		Kind: tenantseal.WrapperKindLocalFile, ID: "tenant-a-custody",
	})
	if err != nil {
		t.Fatalf("Migrate tenant A: %v", err)
	}
	if migrated.State != store.TenantKeyDomainStatePartial ||
		migrated.ProgressCompleted != migrated.ProgressTotal ||
		migrated.LegacyHistoryExposure != store.TenantKeyLegacyExternalArchivesPossible {
		t.Fatalf("migrated status = %+v", migrated)
	}

	access, err := tenantseal.NewAccess(s, deployment, registry)
	if err != nil {
		t.Fatal(err)
	}
	migratedA := readCredentialCiphertext(t, s, tenantA)
	if bytes.Equal(migratedA, legacyA) {
		t.Fatal("tenant A credential remained deployment-domain ciphertext")
	}
	if got := readCredentialCiphertext(t, s, tenantB); !bytes.Equal(got, legacyB) {
		t.Fatal("tenant B credential changed during tenant A migration")
	}
	if err := access.WithTenant(ctx, tenantA, func(cipher tenantseal.Cipher) error {
		plain, err := cipher.Open(migratedA, aadA)
		if err != nil {
			return err
		}
		if !bytes.Equal(plain, []byte("tenant-a-secret")) {
			return errors.New("tenant A plaintext changed")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := access.WithTenant(ctx, tenantB, func(cipher tenantseal.Cipher) error {
		if _, err := cipher.Open(migratedA, aadA); !errors.Is(err, seal.ErrDomain) {
			return errors.New("tenant B resolver accepted tenant A domain")
		}
		plain, err := cipher.Open(legacyB, aadB)
		if err != nil {
			return err
		}
		if !bytes.Equal(plain, []byte("tenant-b-secret")) {
			return errors.New("tenant B plaintext changed")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	sealedState, err := lifecycle.Seal(ctx, tenantA)
	if err != nil || sealedState.State != store.TenantKeyDomainStateSealed {
		t.Fatalf("Seal state=%+v err=%v", sealedState, err)
	}
	if err := access.WithTenant(ctx, tenantA, func(tenantseal.Cipher) error {
		return errors.New("sealed tenant callback ran")
	}); err == nil {
		t.Fatal("sealed tenant A retained crypto access")
	} else if status, ok := tenantseal.StatusOf(err); !ok || status != tenantseal.StatusSealed {
		t.Fatalf("sealed tenant status = %q/%v err=%v", status, ok, err)
	}
	if err := access.WithTenant(ctx, tenantB, func(cipher tenantseal.Cipher) error {
		_, err := cipher.Open(legacyB, aadB)
		return err
	}); err != nil {
		t.Fatalf("tenant B stopped while tenant A was sealed: %v", err)
	}

	unsealedState, err := lifecycle.Unseal(ctx, tenantA)
	if err != nil || unsealedState.State != store.TenantKeyDomainStateUnsealed {
		t.Fatalf("Unseal state=%+v err=%v", unsealedState, err)
	}
	if err := access.WithTenant(ctx, tenantA, func(cipher tenantseal.Cipher) error {
		_, err := cipher.Open(migratedA, aadA)
		return err
	}); err != nil {
		t.Fatalf("tenant A did not recover after unseal: %v", err)
	}

	foundMigratedHistory := false
	if err := log.Replay(ctx, 0, func(event events.Event) error {
		if event.ID != "tenant-domain-source-"+tenantA {
			return nil
		}
		var body struct {
			Sealed []byte `json:"sealed"`
		}
		if err := json.Unmarshal(event.Data, &body); err != nil {
			return err
		}
		if bytes.Equal(body.Sealed, legacyA) {
			return errors.New("tenant A hot history retained deployment-domain ciphertext")
		}
		foundMigratedHistory = true
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !foundMigratedHistory {
		t.Fatal("tenant A migrated history event not found")
	}
}

func readCredentialCiphertext(t *testing.T, s *store.Store, tenantID string) []byte {
	t.Helper()
	var sealed []byte
	if err := s.WithTenant(context.Background(), tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(),
			`SELECT sealed FROM credentials WHERE tenant_id = $1 AND name = 'token'`, tenantID).
			Scan(&sealed)
	}); err != nil {
		t.Fatal(err)
	}
	return sealed
}
