// SPDX-License-Identifier: BUSL-1.1

package eventprivacy_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/eventprivacy"
	"trstctl.com/trstctl/internal/eventprotect"
	"trstctl.com/trstctl/internal/events"
)

// Real NATS and independent file custody, with a local test signer/lock and an
// exact fixture authorizer. Not production outbox/hold/signer-process evidence.
func TestGuardedLateDestructionCompletionPreservesNewKeyAndFirstTerminalIdentity(t *testing.T) {
	base := t.TempDir()
	guard := &sourceFixtureLocker{}
	signer, err := jose.GenerateRSASigningKey("late-guarded-source-fixture")
	if err != nil {
		t.Fatal(err)
	}
	authorizer := &sourceReadDestructionAuthority{}
	keys, err := eventprotect.NewFileAuthority(eventprotect.FileAuthorityConfig{Directory: filepath.Join(base, "keys"), BackupRoots: []string{filepath.Join(base, "events")}, Locker: guard, EvidenceKey: signer, DestructionAuthority: authorizer})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = keys.Close() })
	admission := &eventprivacy.SourceAdmission{Guard: guard, Custody: keys, Policy: eventprivacy.SourcePolicy{Trust: signer.JWKS()}}
	reader := &eventprivacy.SourceKeys{Custody: keys, Policy: eventprivacy.SourcePolicy{Trust: signer.JWKS()}}
	log, err := events.Open(t.Context(), config.NATS{Mode: config.NATSEmbedded, StoreDir: filepath.Join(base, "events")},
		func(log *events.Log) {
			admission.Policy.Log = log
			reader.Policy.Log = log
			admission.Holds = eventprivacy.RetainedHoldPolicy{Policy: admission.Policy}
		}, events.WithEventProtection(events.EventProtection{Admission: admission, Keys: reader}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	activate := func(identity string) eventprotect.KeyRef {
		t.Helper()
		registration := appendSource(t, log, identity, "tenant.registered", time.Now().UTC(), struct {
			Name string `json:"name"`
		}{"fixture"})
		request, err := eventprivacy.NewRequested(sourceTenant, registration.ID, 2*time.Millisecond)
		if err != nil {
			t.Fatal(err)
		}
		requested := appendSource(t, log, eventprivacy.RequestedEventID(request), eventprivacy.EventRequested, time.Now().UTC(), request)
		ref := eventprotect.KeyRef{TenantID: sourceTenant, ID: request.KeyID}
		if err := keys.Provision(t.Context(), ref); err != nil {
			t.Fatal(err)
		}
		creation, err := keys.CreationEvidence(t.Context(), ref)
		if err != nil {
			t.Fatal(err)
		}
		activation := eventprivacy.Activated{RegistrationIdentity: registration.ID, OperationID: request.OperationID, KeyID: request.KeyID, RetentionNanos: request.RetentionNanos, RequestedEventID: requested.ID, RequestedSequence: requested.Sequence, RequestedAt: requested.Time, Creation: creation}
		appendSource(t, log, request.KeyID, eventprivacy.EventActivated, creation.CreatedAt, activation)
		return ref
	}
	oldRef := activate("late-guarded-old-registration")
	oldPrivate := appendSource(t, log, "late-guarded-old-private", sourcePrivateType, time.Now().UTC(), struct {
		Email string `json:"email"`
	}{"old-private@example.invalid"})
	appendSource(t, log, "late-guarded-old-offboard", "tenant.offboarded", time.Now().UTC(), struct {
		RowsDeleted int `json:"rows_deleted"`
	}{0})
	oldLife, err := reader.Policy.LatestLifetime(t.Context(), sourceTenant)
	if err != nil {
		t.Fatal(err)
	}
	authorizer.want, err = eventprivacy.NewDestructionRequest(oldLife)
	if err != nil {
		t.Fatal(err)
	}
	newRef := activate("late-guarded-new-registration")
	if newRef == oldRef {
		t.Fatal("new lifetime reused old key")
	}
	newPrivate := appendSource(t, log, "late-guarded-new-private", sourcePrivateType, time.Now().UTC(), struct {
		Email string `json:"email"`
	}{"new-private@example.invalid"})
	rawBefore := map[uint64][]byte{}
	if err := log.ExportBackupHistoryThrough(t.Context(), newPrivate.Sequence, func(record events.BackupHistoryRecord) error {
		if record.Sequence == oldPrivate.Sequence || record.Sequence == newPrivate.Sequence {
			rawBefore[record.Sequence] = bytes.Clone(record.Stored)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(rawBefore) != 2 {
		t.Fatal("fixture did not independently capture both ciphertext records")
	}
	creation, err := keys.CreationEvidence(t.Context(), newRef)
	if err != nil {
		t.Fatal(err)
	}
	if pause := time.Until(authorizer.want.NotBefore); pause > 0 {
		timer := time.NewTimer(pause)
		select {
		case <-timer.C:
		case <-t.Context().Done():
			timer.Stop()
			t.Fatal(t.Context().Err())
		}
	}
	receipt, err := keys.Destroy(t.Context(), authorizer.want)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := eventprotect.VerifyDestructionReceipt(signer.JWKS(), receipt)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := json.Marshal(eventprivacy.Destroyed{JWS: receipt})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := log.Append(t.Context(), events.Event{ID: "late-guarded-cross-tenant-completed", Type: eventprivacy.EventDestroyed, TenantID: "22222222-2222-2222-2222-222222222222", SchemaVersion: 1, Time: claims.RemovedAt, Data: wire}); !errors.Is(err, eventprivacy.ErrSource) {
		t.Fatalf("receipt crossed its tenant before terminal publication: %v", err)
	}
	completion, err := log.Append(t.Context(), events.Event{ID: "late-guarded-old-completed", Type: eventprivacy.EventDestroyed, TenantID: sourceTenant, SchemaVersion: 1, Time: claims.RemovedAt, Data: wire})
	if err != nil {
		t.Fatalf("old lifetime completion refused after new activation: %v", err)
	}
	if _, err := log.Append(t.Context(), events.Event{ID: "late-guarded-different-completed", Type: eventprivacy.EventDestroyed, TenantID: sourceTenant, SchemaVersion: 1, Time: claims.RemovedAt, Data: wire}); !errors.Is(err, eventprivacy.ErrSource) {
		t.Fatalf("second completion identity entered immutable source: %v", err)
	}
	retry, err := log.Append(t.Context(), events.Event{ID: completion.ID, Type: eventprivacy.EventDestroyed, TenantID: sourceTenant, SchemaVersion: 1, Data: wire})
	if err != nil || retry.Sequence != completion.Sequence {
		t.Fatalf("implicit-time terminal retry lost first identity: %v", err)
	}
	old, found, err := log.EventByID(t.Context(), oldPrivate.ID)
	if err != nil || !found || !old.SensitiveErased || old.Data != nil {
		t.Fatalf("old key's fields did not erase: %v", err)
	}
	current, found, err := log.EventByID(t.Context(), newPrivate.ID)
	if err != nil || !found || current.SensitiveErased || !bytes.Equal(current.Data, newPrivate.Data) {
		t.Fatalf("old destruction changed new lifetime's readable fields: %v", err)
	}
	after, err := keys.CreationEvidence(t.Context(), newRef)
	if err != nil || after.Digest() != creation.Digest() {
		t.Fatalf("old destruction changed new key: %v", err)
	}
	if err := log.ExportBackupHistoryThrough(t.Context(), newPrivate.Sequence, func(record events.BackupHistoryRecord) error {
		if before, ok := rawBefore[record.Sequence]; ok && !bytes.Equal(before, record.Stored) {
			t.Fatal("late completion rewrote immutable ciphertext")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
