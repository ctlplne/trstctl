// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/tenantseal"
)

// TestTenantKeyDomainLifecycleRotatesOneTenantToItsNextGeneration proves the
// real PostgreSQL + embedded-JetStream rotation path: a rotation whose history
// rewrite fails stays resumable and reads both generations, the retry promotes
// generation 2 so generation 1 no longer opens, a second rotation moves the
// domain onto another wrapper so the first wrapper is no longer needed, and the
// neighbor tenant never changes.
func TestTenantKeyDomainLifecycleRotatesOneTenantToItsNextGeneration(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	for _, tenantID := range []string{tenantA, tenantB} {
		if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenantID, Name: tenantID}); err != nil {
			t.Fatal(err)
		}
	}
	deployment := migrationTestKEK(t, 0x61)
	wrapperPaths := map[string]string{}
	for id, fill := range map[string]byte{"tenant-a-custody": 0x62, "tenant-a-custody-next": 0x63} {
		path := filepath.Join(t.TempDir(), id+".key")
		if err := os.WriteFile(path, bytes.Repeat([]byte{fill}, 32), 0o600); err != nil {
			t.Fatal(err)
		}
		wrapperPaths[id] = path
	}
	registry, err := tenantseal.NewLocalWrapperRegistry([]tenantseal.LocalWrapper{
		{ID: "tenant-a-custody", Path: wrapperPaths["tenant-a-custody"]},
		{ID: "tenant-a-custody-next", Path: wrapperPaths["tenant-a-custody-next"]},
	})
	if err != nil {
		t.Fatal(err)
	}
	log, rewriteOptions := openTenantKeyDomainHistory(t, s)
	lifecycle, err := tenantseal.NewLifecycle(s, log, deployment, registry, rewriteOptions...)
	if err != nil {
		t.Fatal(err)
	}
	access, err := tenantseal.NewAccess(s, deployment, registry)
	if err != nil {
		t.Fatal(err)
	}

	aad := map[string][]byte{tenantA: []byte("credential:tenant-a"), tenantB: []byte("credential:tenant-b")}
	legacy := map[string][]byte{}
	for index, tenantID := range []string{tenantA, tenantB} {
		sealed, err := seal.Seal(deployment, []byte("secret of "+tenantID), aad[tenantID])
		if err != nil {
			t.Fatal(err)
		}
		legacy[tenantID] = sealed
		if err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx,
				`INSERT INTO credentials (id, tenant_id, scope, ref, name, sealed)
				 VALUES ($1, $2, 'connector', 'target', 'token', $3)`,
				uuid(tenantID, index+190), tenantID, sealed)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		data, err := json.Marshal(map[string]any{"sealed": sealed})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := log.Append(ctx, events.Event{
			ID:   "tenant-rotation-source-" + tenantID,
			Type: "secret.version.written", TenantID: tenantID,
			Time: time.Now().UTC(), Data: data,
		}); err != nil {
			t.Fatal(err)
		}
	}

	if _, err := lifecycle.Rotate(ctx, tenantA, tenantseal.WrapperRef{}); !errors.Is(err, tenantseal.ErrLifecycleConflict) {
		t.Fatalf("a deployment-key tenant rotated before migrating: %v", err)
	}
	migrated, err := lifecycle.Migrate(ctx, tenantA, tenantseal.WrapperRef{
		Kind: tenantseal.WrapperKindLocalFile, ID: "tenant-a-custody",
	})
	if err != nil {
		t.Fatalf("Migrate tenant A: %v", err)
	}
	generationOne := readCredentialCiphertext(t, s, tenantA)
	opens := func(t *testing.T, access tenantseal.Access, container []byte) {
		t.Helper()
		if err := access.WithTenant(ctx, tenantA, func(cipher tenantseal.Cipher) error {
			plain, err := cipher.Open(container, aad[tenantA])
			if err != nil {
				return err
			}
			if string(plain) != "secret of "+tenantA {
				return errors.New("tenant A plaintext changed")
			}
			return nil
		}); err != nil {
			t.Fatalf("tenant A container did not open: %v", err)
		}
	}
	labeled := func(t *testing.T, container []byte, generation int64) {
		t.Helper()
		want, err := tenantseal.DomainBinding(tenantA, migrated.DomainID, generation)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := seal.Domain(container); err != nil || !bytes.Equal(got, want) {
			t.Fatalf("container label = %q, %v; want generation %d", got, err, generation)
		}
	}

	// A rotation whose history rewrite fails stays resumable and reads both
	// generations: hot state already moved, history still holds generation 1.
	failingOptions := append(append([]events.TenantDataRewriteOption(nil), rewriteOptions...),
		events.WithTenantDataContinuity(func(context.Context, events.TenantDataRewriteReport) (events.Event, error) {
			return events.Event{}, errors.New("continuity signer offline")
		}))
	failing, err := tenantseal.NewLifecycle(s, log, deployment, registry, failingOptions...)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := failing.Rotate(ctx, tenantA, tenantseal.WrapperRef{}); err == nil {
		t.Fatal("rotation completed without its continuity receipt")
	}
	stuck, err := lifecycle.Status(ctx, tenantA)
	if err != nil || stuck.State != store.TenantKeyDomainStateRotating ||
		stuck.OperationKind != store.TenantKeyOperationRotate ||
		stuck.OperationStatus != store.TenantKeyOperationFailed || !stuck.Retryable ||
		stuck.LastErrorCode != "hot_history_rewrite_failed" ||
		stuck.Generation != 1 || stuck.NextGeneration != 2 {
		t.Fatalf("failed rotation state = %+v err=%v", stuck, err)
	}
	hot := readCredentialCiphertext(t, s, tenantA)
	labeled(t, hot, 2)
	opens(t, access, hot)
	opens(t, access, generationOne)
	labeled(t, rotationHistorySealed(t, log, tenantA), 1)
	if _, err := lifecycle.RequestSeal(ctx, tenantA, "seal-during-rotation", strings.Repeat("c", 64)); !errors.Is(err, tenantseal.ErrLifecycleConflict) {
		t.Fatalf("a seal was queued during a rotation: %v", err)
	}
	if _, err := lifecycle.Rotate(ctx, tenantA, tenantseal.WrapperRef{
		Kind: tenantseal.WrapperKindLocalFile, ID: "tenant-a-custody-next",
	}); !errors.Is(err, tenantseal.ErrLifecycleConflict) {
		t.Fatalf("a failed rotation was retargeted instead of resumed: %v", err)
	}

	// The retry resumes and promotes generation 2 under the same wrapper; the
	// retired generation no longer opens anywhere in hot state or history.
	rotated, err := lifecycle.Rotate(ctx, tenantA, tenantseal.WrapperRef{})
	if err != nil {
		t.Fatalf("resume rotation: %v", err)
	}
	if rotated.State != store.TenantKeyDomainStateUnsealed ||
		rotated.OperationKind != store.TenantKeyOperationRotate ||
		rotated.OperationStatus != store.TenantKeyOperationCompleted ||
		rotated.Generation != 2 || rotated.WrapperID != "tenant-a-custody" ||
		rotated.NextGeneration != 0 || rotated.NextWrappedDomainKEK != nil || rotated.RotatedAt == nil ||
		bytes.Equal(rotated.WrappedDomainKEK, migrated.WrappedDomainKEK) ||
		rotated.LegacyHistoryExposure != migrated.LegacyHistoryExposure {
		t.Fatalf("rotated state = %+v", rotated)
	}
	labeled(t, rotationHistorySealed(t, log, tenantA), 2)
	opens(t, access, readCredentialCiphertext(t, s, tenantA))
	opens(t, access, rotationHistorySealed(t, log, tenantA))
	if err := access.WithTenant(ctx, tenantA, func(cipher tenantseal.Cipher) error {
		if _, err := cipher.Open(generationOne, aad[tenantA]); !errors.Is(err, seal.ErrDomain) {
			return errors.New("the retired generation still opens after the rotation")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	// Rotating onto another wrapper leaves the first wrapper unneeded.
	moved, err := lifecycle.Rotate(ctx, tenantA, tenantseal.WrapperRef{
		Kind: tenantseal.WrapperKindLocalFile, ID: "tenant-a-custody-next",
	})
	if err != nil || moved.Generation != 3 || moved.WrapperID != "tenant-a-custody-next" {
		t.Fatalf("rotate onto the next wrapper = %+v err=%v", moved, err)
	}
	onlyNext, err := tenantseal.NewLocalWrapperRegistry([]tenantseal.LocalWrapper{
		{ID: "tenant-a-custody-next", Path: wrapperPaths["tenant-a-custody-next"]},
	})
	if err != nil {
		t.Fatal(err)
	}
	accessNext, err := tenantseal.NewAccess(s, deployment, onlyNext)
	if err != nil {
		t.Fatal(err)
	}
	opens(t, accessNext, readCredentialCiphertext(t, s, tenantA))
	opens(t, accessNext, rotationHistorySealed(t, log, tenantA))

	// A target wrapper that is not configured is refused before anything changes.
	if _, err := lifecycle.Rotate(ctx, tenantA, tenantseal.WrapperRef{
		Kind: tenantseal.WrapperKindLocalFile, ID: "not-configured",
	}); !errors.Is(err, tenantseal.ErrWrapperNotConfigured) {
		t.Fatalf("rotation onto an unconfigured wrapper = %v", err)
	}
	unchanged, err := lifecycle.Status(ctx, tenantA)
	if err != nil || unchanged.Generation != 3 ||
		unchanged.LastTransitionType != projections.EventTenantKeyDomainRotationCompleted {
		t.Fatalf("a refused rotation changed the domain: %+v err=%v", unchanged, err)
	}

	if got := readCredentialCiphertext(t, s, tenantB); !bytes.Equal(got, legacy[tenantB]) {
		t.Fatal("tenant B credential changed during tenant A rotations")
	}
	if _, err := s.GetTenantKeyDomain(ctx, tenantB); !errors.Is(err, store.ErrTenantKeyDomainNotFound) {
		t.Fatalf("tenant B gained a key domain: %v", err)
	}
	if !bytes.Equal(rotationHistorySealed(t, log, tenantB), legacy[tenantB]) {
		t.Fatal("tenant B history changed during tenant A rotations")
	}
}

// rotationHistorySealed reads the sealed bytes of a tenant's fixture event as
// the active event-log generation holds them now.
func rotationHistorySealed(t *testing.T, log *events.Log, tenantID string) []byte {
	t.Helper()
	var sealed []byte
	if err := log.Replay(context.Background(), 0, func(event events.Event) error {
		if event.ID != "tenant-rotation-source-"+tenantID {
			return nil
		}
		var body struct {
			Sealed []byte `json:"sealed"`
		}
		if err := json.Unmarshal(event.Data, &body); err != nil {
			return err
		}
		sealed = body.Sealed
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if sealed == nil {
		t.Fatalf("history event for tenant %s not found", tenantID)
	}
	return sealed
}
