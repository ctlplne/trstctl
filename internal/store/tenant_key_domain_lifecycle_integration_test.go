// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"trstctl.com/trstctl/internal/eventstest"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/storetest"
	"trstctl.com/trstctl/internal/tenantseal"
)

func tenantTransitionAfterOrphanedPairProof(t *testing.T, s *store.Store, label string,
	run func(context.Context) (store.TenantKeyDomain, error),
) (store.TenantKeyDomain, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	var proofTx pgx.Tx
	if err := s.WithGlobalKeyStateAdmission(ctx, store.KeyStateShared, func(admitted context.Context) error {
		var err error
		proofTx, err = s.SystemPool().Begin(admitted)
		if err != nil {
			return err
		}
		return s.LockGlobalKeyStateCommitTx(admitted, proofTx, store.KeyStateShared)
	}); err != nil {
		t.Fatalf("hold pair transaction before %s: %v", label, err)
	}
	t.Cleanup(func() { _ = proofTx.Rollback(context.Background()) })
	type result struct {
		domain store.TenantKeyDomain
		err    error
	}
	done := make(chan result, 1)
	go func() {
		domain, err := run(ctx)
		done <- result{domain: domain, err: err}
	}()
	select {
	case got := <-done:
		t.Fatalf("%s crossed orphaned pair transaction: %v", label, got.err)
	case <-time.After(2 * time.Second):
	}
	if err := proofTx.Rollback(ctx); err != nil {
		t.Fatalf("release pair transaction before %s: %v", label, err)
	}
	select {
	case got := <-done:
		return got.domain, got.err
	case <-ctx.Done():
		t.Fatalf("%s did not finish after pair transaction ended", label)
		return store.TenantKeyDomain{}, ctx.Err()
	}
}

// TestTenantKeyDomainLifecycleMigratesSealsAndUnsealsOneTenant proves the real
// PostgreSQL + embedded-JetStream path: tenant A's hot rows and event history
// move without payload plaintext, sealing A does not stop B, and neither
// tenant's resolver can use the other's protection domain.
func TestTenantKeyDomainLifecycleMigratesSealsAndUnsealsOneTenant(t *testing.T) {
	s := storetest.OpenRewrapCutoverStore(t, newStore(t), testDSN)
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

	log, rewriteOptions := openTenantKeyDomainHistory(t, s, deployment)
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

	exhaustedState, err := tenantTransitionAfterOrphanedPairProof(t, s, "RequestSeal",
		func(callCtx context.Context) (store.TenantKeyDomain, error) {
			return lifecycle.RequestSeal(callCtx, tenantA, "tenant-a-seal-exhausted", strings.Repeat("a", 64))
		})
	if err != nil || exhaustedState.State != store.TenantKeyDomainStateSealQueued ||
		exhaustedState.OperationID == nil {
		t.Fatalf("RequestSeal exhausted fixture state=%+v err=%v", exhaustedState, err)
	}
	failedState, err := tenantTransitionAfterOrphanedPairProof(t, s, "FailSeal",
		func(callCtx context.Context) (store.TenantKeyDomain, error) {
			return lifecycle.FailSeal(callCtx, tenantA, *exhaustedState.OperationID)
		})
	if err != nil || failedState.State != store.TenantKeyDomainStatePartial ||
		failedState.OperationStatus != store.TenantKeyOperationFailed ||
		!failedState.Retryable || failedState.LastErrorCode != "seal_delivery_exhausted" {
		t.Fatalf("FailSeal state=%+v err=%v", failedState, err)
	}
	if err := access.WithTenant(ctx, tenantA, func(cipher tenantseal.Cipher) error {
		_, err := cipher.Open(migratedA, aadA)
		return err
	}); err != nil {
		t.Fatalf("tenant A crypto stopped after a seal that never committed: %v", err)
	}

	queuedState, err := lifecycle.RequestSeal(
		ctx, tenantA, "tenant-a-seal-retry", strings.Repeat("b", 64),
	)
	if err != nil || queuedState.State != store.TenantKeyDomainStateSealQueued ||
		queuedState.OperationStatus != store.TenantKeyOperationPending ||
		queuedState.OperationID == nil || *queuedState.OperationID == *exhaustedState.OperationID {
		t.Fatalf("RequestSeal retry state=%+v err=%v", queuedState, err)
	}
	// A queued request is not a pretend seal. Existing work stays available until
	// the result-cache wall is complete and the bounded worker owns the exclusive
	// fence.
	if err := access.WithTenant(ctx, tenantA, func(cipher tenantseal.Cipher) error {
		_, err := cipher.Open(migratedA, aadA)
		return err
	}); err != nil {
		t.Fatalf("tenant A stopped before the bounded seal worker: %v", err)
	}

	sealedState, err := tenantTransitionAfterOrphanedPairProof(t, s, "CompleteSeal",
		func(callCtx context.Context) (store.TenantKeyDomain, error) {
			return lifecycle.CompleteSeal(callCtx, tenantA, *queuedState.OperationID)
		})
	if err != nil || sealedState.State != store.TenantKeyDomainStateSealed {
		t.Fatalf("CompleteSeal state=%+v err=%v", sealedState, err)
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

	unsealedState, err := tenantTransitionAfterOrphanedPairProof(t, s, "Unseal",
		func(callCtx context.Context) (store.TenantKeyDomain, error) {
			return lifecycle.Unseal(callCtx, tenantA)
		})
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

// openTenantKeyDomainHistory opens the real embedded JetStream log with the
// cross-store history-rewrite coordinator and receipt verifier, and returns the
// rewrite proof walls a lifecycle needs: backup-fence cutover preparation,
// audit continuity, and a continuity receipt.
func openTenantKeyDomainHistory(t *testing.T, s *store.Store, deployment seal.KeyWrapper) (*events.Log, []events.TenantDataRewriteOption) {
	t.Helper()
	log, err := eventstest.OpenFixture(
		context.Background(),
		config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()},
		events.WithAppendAdmission(func(ctx context.Context, event events.Event,
			publish func(context.Context) (events.Event, error),
		) (events.Event, error) {
			if event.Type == "secret.version.written" {
				var payload struct {
					Sealed       []byte `json:"sealed"`
					TenantMarker string `json:"tenant_marker"`
				}
				if err := json.Unmarshal(event.Data, &payload); err != nil {
					return events.Event{}, err
				}
				if len(payload.Sealed) == 0 || payload.TenantMarker != "" && payload.TenantMarker != event.TenantID {
					return events.Event{}, errors.New("tenant-domain fixture container or tenant marker is invalid")
				}
				var aad []byte
				switch event.TenantID {
				case tenantA:
					aad = []byte("credential:tenant-a")
				case tenantB:
					aad = []byte("credential:tenant-b")
				default:
					return events.Event{}, errors.New("tenant-domain fixture tenant is unknown")
				}
				plaintext, err := seal.OpenIntoLocked(deployment, payload.Sealed, aad, nil)
				if err != nil {
					return events.Event{}, err
				}
				plaintext.Destroy()
			} else if storeFixtureHasSealedField(event.Data) {
				return events.Event{}, fmt.Errorf("unclassified tenant-domain fixture sealed event %s", event.Type)
			}
			// CR-045: every key-state snapshot borrows an exclusive owner B.
			// Its history read session must already be held before B opens.
			if events.RequiresExclusiveKeyStateAdmission(event.Type) &&
				!events.IngressHistoryReadPreheld(ctx) {
				return events.Event{}, fmt.Errorf("CR-045 lifecycle snapshot %s opened B before history A", event.Type)
			}
			return publish(ctx)
		}),
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

	return log, []events.TenantDataRewriteOption{
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
}

func storeFixtureHasSealedField(data []byte) bool {
	var value any
	if err := json.Unmarshal(data, &value); err != nil {
		lower := strings.ToLower(string(data))
		return strings.Contains(lower, "sealed") || strings.Contains(lower, "ciphertext")
	}
	var walk func(any) bool
	walk = func(current any) bool {
		switch typed := current.(type) {
		case map[string]any:
			for name, child := range typed {
				lower := strings.ToLower(name)
				metadata := lower == "sealed_at" || lower == "sealed_sha256" ||
					lower == "sealed_only_floor" || lower == "sealed_results" ||
					lower == "sealed_tenants_not_opened" || lower == "sealed_copies" ||
					lower == "ciphertext_sha256"
				if !metadata && (lower == "sealed" || strings.HasPrefix(lower, "sealed_") ||
					lower == "requester_sealed" || lower == "ciphertext" || strings.HasPrefix(lower, "ciphertext_")) {
					return true
				}
				if walk(child) {
					return true
				}
			}
		case []any:
			for _, child := range typed {
				if walk(child) {
					return true
				}
			}
		}
		return false
	}
	return walk(value)
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
