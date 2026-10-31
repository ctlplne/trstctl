// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/bulkhead"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/eventprivacy"
	"trstctl.com/trstctl/internal/eventprotect"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// Actual configured delivery/pool/source/custody and warm reopening. This signer
// and source request are explicit local fixtures; OS-process kill and isolated
// signer/private-key runtime qualification remain separate final replay work.
type interruptedEventKeyBootSigner struct {
	key     *jose.SigningKey
	fail    atomic.Bool
	refused atomic.Int64
	calls   atomic.Int64
}

func (s *interruptedEventKeyBootSigner) SignArtifact(kind string, payload []byte) (string, error) {
	if kind == jose.ArtifactEventKeyDestruction {
		s.calls.Add(1)
	}
	if kind == jose.ArtifactEventKeyDestruction && s.fail.Load() {
		s.refused.Add(1)
		return "", errors.New("fixture destruction signer interrupted after removal")
	}
	return s.key.SignArtifact(kind, payload)
}

func TestEventProtectionInterruptedRemovalRecoversBeforeSanitizedStartup(t *testing.T) {
	for _, mode := range []string{"original-intent", "missing-original-intent"} {
		t.Run(mode, func(t *testing.T) { eventProtectionInterruptedStartup(t, mode) })
	}
}
func eventProtectionInterruptedStartup(t *testing.T, mode string) {
	st := newServerTestStore(t)
	cfg := eventProtectionRuntimeConfigFixture(t)
	cfg.Postgres.Mode = config.PostgresExternal
	cfg.Postgres.DSN = serverTestPostgresDSN(t)
	cfg.NATS.Mode = config.NATSExternal
	cfg.NATS.URL = startBackupTestNATS(t).ClientURL()
	cfg.NATS.Replicas = 1
	cfg.NATS.AllowSingleReplica = true
	locked, err := crypto.GenerateLockedKey(crypto.RSA2048)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(locked.Destroy)
	local, err := jose.NewDigestSigningKey("a233-startup-component-fixture", locked)
	if err != nil {
		t.Fatal(err)
	}
	remote := &interruptedEventKeyBootSigner{key: local}
	key, err := jose.NewArtifactSigningKey("a233-startup-component-fixture", locked.Public(), remote)
	if err != nil {
		t.Fatal(err)
	}
	log, runtime, err := openConfiguredEventSource(t.Context(), cfg, st, key, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runtime.Close() })
	t.Cleanup(func() { _ = log.Close() })
	const tenant = "c6c9f597-d2cb-4754-bd52-682e4be0cce2"
	const neighbor = "d074fd2a-38ba-4924-865a-eb58de2b1177"
	registration, err := log.Append(t.Context(), events.Event{Type: projections.EventTenantRegistered, TenantID: tenant, Data: []byte(`{"name":"Erased rebuild fixture"}`)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := log.Append(t.Context(), events.Event{Type: projections.EventTenantRegistered, TenantID: neighbor, Data: []byte(`{"name":"Rebuild neighbor"}`)}); err != nil {
		t.Fatal(err)
	}
	requested, err := eventprivacy.NewRequested(tenant, registration.ID, time.Nanosecond)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := json.Marshal(requested)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := log.Append(t.Context(), events.Event{ID: eventprivacy.RequestedEventID(requested), Type: eventprivacy.EventRequested, TenantID: tenant, Data: wire}); err != nil {
		t.Fatal(err)
	}
	if err := projections.New(st, runtime.projectionOptions()...).Rebuild(t.Context(), log); err != nil {
		t.Fatal(err)
	}
	srv, err := Build(t.Context(), Deps{Store: st, Log: log, AuditSigningKey: key, eventProtection: runtime})
	if err != nil {
		t.Fatal(err)
	}
	stopped := false
	defer func() {
		if !stopped {
			_ = srv.Shutdown(t.Context())
		}
	}()
	if err := srv.Drain(t.Context()); err != nil {
		t.Fatal(err)
	}
	owner, err := srv.orch.CreateOwner(t.Context(), tenant, "team", "Erased owner", "erased-rebuild@example.invalid")
	if err != nil {
		t.Fatal(err)
	}
	other, err := srv.orch.CreateOwner(t.Context(), neighbor, "team", "Neighbor owner", "rebuild-neighbor@example.invalid")
	if err != nil {
		t.Fatal(err)
	}
	head, err := log.LastSequence(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	var private events.Event
	if err := log.ReplayTenantTypesThrough(t.Context(), tenant, 1, head, []string{projections.EventOwnerCreated}, func(event events.Event) error {
		if bytes.Contains(event.Data, []byte(owner.ID)) {
			private = event
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if private.ID == "" || private.Protection == nil {
		t.Fatal("fixture did not protect actual owner event")
	}
	remote.fail.Store(true)
	if _, err := srv.orch.OffboardTenant(t.Context(), orchestrator.TenantOffboardCommand{TenantID: tenant, RegistrationIdentity: registration.ID}); err != nil {
		t.Fatal(err)
	}
	var family outboxDispatchFamily
	for _, candidate := range outboxDispatchFamilies {
		if candidate.eventKeyKind == 2 {
			family = candidate
			break
		}
	}
	if family.eventKeyKind != 2 {
		t.Fatal("missing destruction family")
	}
	workCtx, cancelWork := context.WithTimeout(t.Context(), 8*time.Second)
	defer cancelWork()
	done := make(chan struct{})
	var dispatchErr error
	if err := srv.bulk.Pool(bulkhead.SubsystemOutboxEventKeyDestruction).Submit(func() { defer close(done); _, dispatchErr = srv.dispatchOutboxFamily(workCtx, family) }); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-workCtx.Done():
		t.Fatal("actual destruction pool did not finish first attempt")
	}
	_ = dispatchErr // Effect failure may be recorded as a retry by the actual outbox.
	if remote.refused.Load() == 0 {
		t.Fatal("fixture never reached destruction signing after removal")
	}
	ref := eventprotect.KeyRef{TenantID: tenant, ID: requested.KeyID}
	if _, err := os.Stat(filepath.Join(cfg.Privacy.EventProtection.KeyDirectory, ref.TenantID, ref.ID+".key")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("first attempt did not actually unlink owned key material: %v", err)
	}
	metadata, err := os.ReadFile(filepath.Join(cfg.Privacy.EventProtection.KeyDirectory, ref.TenantID, ref.ID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var journal struct {
		Phase       string `json:"phase"`
		Destruction *struct {
			RemovedAt time.Time `json:"removed_at"`
			Receipt   string    `json:"receipt"`
		} `json:"destruction"`
	}
	if err := json.Unmarshal(metadata, &journal); err != nil || journal.Phase != "destroying" || journal.Destruction == nil || journal.Destruction.RemovedAt.IsZero() || journal.Destruction.Receipt != "" {
		t.Fatalf("no actual incomplete removal journal: %v", err)
	}
	if _, erased, err := runtime.custody.DestructionReceipt(t.Context(), ref); err == nil || erased {
		t.Fatal("incomplete signature was reported as verified erasure")
	}
	life, err := runtime.policy.LatestLifetime(t.Context(), tenant)
	if err != nil || life.Offboard == nil || life.HoldClearance == nil || life.Completion != nil {
		t.Fatalf("interruption lost exact retained authority: %v", err)
	}
	expected, err := eventprivacy.NewDestructionRequest(life)
	if err != nil {
		t.Fatal(err)
	}
	if mode == "missing-original-intent" {
		if err := st.WithTenant(t.Context(), tenant, func(tx pgx.Tx) error {
			tag, err := tx.Exec(t.Context(), `DELETE FROM outbox WHERE tenant_id=$1 AND idempotency_key=$2`, tenant, store.EventKeyDestructionOutboxKey(expected.OperationID))
			if err != nil {
				return err
			}
			if tag.RowsAffected() != 1 {
				t.Fatal("fault fixture did not remove its exact owned original intent")
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	// This source event has no SQL projection yet. Recovery must not jump the
	// global checkpoint to the later destruction completion and strand it.
	const lateID = "c33b87cf-ad36-4faa-969a-15ebfd71d878"
	lateWire, err := json.Marshal(projections.OwnerCreated{ID: lateID, Kind: "team", Name: "Boot catch-up neighbor", Email: "boot-neighbor@example.invalid"})
	if err != nil {
		t.Fatal(err)
	}
	late, err := log.Append(t.Context(), events.Event{Type: projections.EventOwnerCreated, TenantID: neighbor, Data: lateWire})
	if err != nil {
		t.Fatal(err)
	}
	head, err = log.LastSequence(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	checkpoint, err := st.ProjectionCheckpoint(t.Context())
	if err != nil || checkpoint >= late.Sequence {
		t.Fatal("fixture neighbor already covered by checkpoint")
	}
	var before bytes.Buffer
	if err := log.ExportBackupHistoryThrough(t.Context(), head, func(record events.BackupHistoryRecord) error { before.Write(record.Stored); return nil }); err != nil {
		t.Fatal(err)
	}
	digest := crypto.SHA256Hex(before.Bytes())
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if err := srv.Shutdown(canceled); err == nil {
		t.Fatal("canceled shutdown unexpectedly drained incomplete work")
	}
	stopped = true
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	remote.fail.Store(false)
	againStore, err := store.Open(t.Context(), cfg.Postgres.DSN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(againStore.Close)
	// Honor real lease TTL/backoff; no SQL resets or forced receiver token edits.
	reopenBudget := 45 * time.Second
	if mode == "missing-original-intent" {
		reopenBudget = 2 * time.Second
	}
	callsBeforeReopen := remote.calls.Load()
	reopenCtx, cancelReopen := context.WithTimeout(t.Context(), reopenBudget)
	defer cancelReopen()
	again, after, err := openConfiguredEventSource(reopenCtx, cfg, againStore, key, true, nil)
	if mode == "missing-original-intent" {
		if err == nil {
			_ = again.Close()
			_ = after.Close()
			t.Fatal("orphan journal resumed without original SQL claim")
		}
		if remote.calls.Load() != callsBeforeReopen {
			t.Fatal("orphan journal requested a new signature")
		}
		current, readErr := os.ReadFile(filepath.Join(cfg.Privacy.EventProtection.KeyDirectory, ref.TenantID, ref.ID+".json"))
		if readErr != nil || !bytes.Equal(current, metadata) {
			t.Fatal("orphan journal changed despite missing original claim")
		}
		raw, reader, readErr := openConfiguredEventSource(t.Context(), cfg, againStore, key, false, nil)
		if readErr != nil {
			t.Fatal(readErr)
		}
		defer func() { _ = raw.Close(); _ = reader.Close() }()
		if got, readErr := raw.LastSequence(t.Context()); readErr != nil || got != head {
			t.Fatalf("orphan recovery invented source: %d %v", got, readErr)
		}
		return
	}
	if err != nil {
		t.Fatalf("normal sanitized startup did not resume original incomplete destruction: %v", err)
	}
	t.Cleanup(func() { _ = after.Close() })
	t.Cleanup(func() { _ = again.Close() })
	if got, err := againStore.ProjectionCheckpoint(t.Context()); err != nil || got != checkpoint {
		t.Fatalf("startup recovery jumped ordered global checkpoint: %d %v", got, err)
	}
	if err := projections.New(againStore, after.projectionOptions()...).ProjectCatchUp(t.Context(), again); err != nil {
		t.Fatal(err)
	}
	got, err := againStore.GetOwner(t.Context(), neighbor, lateID)
	if err != nil || got.Email != "boot-neighbor@example.invalid" {
		t.Fatalf("startup stranded unapplied neighbor: %v", err)
	}
	got, err = againStore.GetOwner(t.Context(), neighbor, other.ID)
	if err != nil || got.Email != other.Email {
		t.Fatalf("startup changed previous neighbor: %v", err)
	}
	actual, found, err := again.EventByID(t.Context(), private.ID)
	if err != nil || !found || !actual.SensitiveErased || len(actual.Data) != 0 {
		t.Fatalf("startup exposed erased private source: %v", err)
	}
	resumed, err := Build(t.Context(), Deps{Store: againStore, Log: again, AuditSigningKey: key, eventProtection: after})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resumed.Shutdown(t.Context()) }()
	if err := resumed.Drain(t.Context()); err != nil {
		t.Fatal(err)
	}
	eventKeyAssertNoTenantSQLResidue(t, againStore, tenant)
	receipt, erased, err := after.custody.DestructionReceipt(t.Context(), ref)
	if err != nil || !erased || receipt == "" {
		t.Fatalf("startup did not verify signed current absence: %v", err)
	}
	claims, err := eventprotect.VerifyDestructionReceipt(key.JWKS(), receipt)
	if err != nil || !claims.RemovedAt.Equal(journal.Destruction.RemovedAt) || claims.Request.CreationDigest != expected.CreationDigest || claims.Request.OffboardSequence != expected.OffboardSequence || claims.Request.OperationID != expected.OperationID {
		t.Fatalf("recovery changed original removal time or source command: %v", err)
	}
	var raw bytes.Buffer
	if err := again.ExportBackupHistoryThrough(t.Context(), head, func(record events.BackupHistoryRecord) error { raw.Write(record.Stored); return nil }); err != nil {
		t.Fatal(err)
	}
	if crypto.SHA256Hex(raw.Bytes()) != digest {
		t.Fatal("startup recovery rewrote retained source prefix")
	}
}
