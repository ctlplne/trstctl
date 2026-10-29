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
	"trstctl.com/trstctl/internal/eventspec"
)

const sourcePrivateType = "a233.source_private"

func init() {
	if err := events.RegisterPrivacyEventPolicy(sourcePrivateType, 1, events.PrivacyEventPolicy{
		Rules: []events.PrivacyFieldRule{{Path: "/email", Mode: events.PrivacyFieldIdentityExact}},
		PayloadShape: events.PrivacyPayloadShapeOf[struct {
			Email string `json:"email"`
		}](),
	}); err != nil {
		panic(err)
	}
	if !events.HasPrivacyEventPolicy("tenant.offboarded", 1) {
		if err := events.RegisterPrivacyEventPolicy("tenant.offboarded", 1, events.PrivacyEventPolicy{
			Rules: []events.PrivacyFieldRule{{Path: "/rows_deleted", Mode: events.PrivacyFieldOpaqueExact}},
			PayloadShape: events.PrivacyPayloadShapeOf[struct {
				RowsDeleted int `json:"rows_deleted"`
			}](),
			RejectSubjectData: true,
		}); err != nil {
			panic(err)
		}
	}
}

// This real NATS/file-custody journey checks the log adapter. Its local signer
// and explicit fixture provision/removal do not qualify the production outbox,
// PostgreSQL lifecycle projection, isolated signer or HTTP/CLI/console workflow.
func TestGuardedLogProtectsAfterActivationAndPreservesCiphertextAfterRemoval(t *testing.T) {
	base := t.TempDir()
	guard := &sourceFixtureLocker{}
	key, err := jose.GenerateRSASigningKey("guarded-log-fixture")
	if err != nil {
		t.Fatal(err)
	}
	authorizer := &sourceReadDestructionAuthority{}
	keys, err := eventprotect.NewFileAuthority(eventprotect.FileAuthorityConfig{Directory: filepath.Join(base, "keys"), BackupRoots: []string{filepath.Join(base, "events")}, Locker: guard, EvidenceKey: key, DestructionAuthority: authorizer})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = keys.Close() })
	admission := &eventprivacy.SourceAdmission{Guard: guard, Custody: keys, Policy: eventprivacy.SourcePolicy{Trust: key.JWKS()}}
	reader := &eventprivacy.SourceKeys{Custody: keys, Policy: eventprivacy.SourcePolicy{Trust: key.JWKS()}}
	log, err := events.Open(t.Context(), config.NATS{Mode: config.NATSEmbedded, StoreDir: filepath.Join(base, "events")},
		func(log *events.Log) {
			admission.Policy.Log = log
			reader.Policy.Log = log
			admission.Holds = eventprivacy.RetainedHoldPolicy{Policy: admission.Policy}
		},
		events.WithEventProtection(events.EventProtection{Admission: admission, Keys: reader}), events.WithDuplicateWindowForTesting(100*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	registration := appendSource(t, log, "guarded-registration", "tenant.registered", time.Now().UTC().Add(-time.Second), struct {
		Name string `json:"name"`
	}{"fixture"})
	legacy := appendSource(t, log, "guarded-legacy", sourcePrivateType, time.Now().UTC(), struct {
		Email string `json:"email"`
	}{"legacy-private@example.invalid"})
	request, err := eventprivacy.NewRequested(sourceTenant, registration.ID, time.Nanosecond)
	if err != nil {
		t.Fatal(err)
	}
	requested := appendSource(t, log, eventprivacy.RequestedEventID(request), eventprivacy.EventRequested, time.Now().UTC(), request)
	if _, err := log.Append(t.Context(), events.Event{ID: "pending-private", Type: sourcePrivateType, TenantID: sourceTenant, Data: []byte(`{"email":"pending@example.invalid"}`)}); !errors.Is(err, eventprivacy.ErrPreparing) {
		t.Fatalf("pending preparation admitted plaintext: %v", err)
	}
	ref := eventprotect.KeyRef{TenantID: sourceTenant, ID: request.KeyID}
	if err := keys.Provision(t.Context(), ref); err != nil {
		t.Fatal(err)
	}
	creation, err := keys.CreationEvidence(t.Context(), ref)
	if err != nil {
		t.Fatal(err)
	}
	activation := eventprivacy.Activated{RegistrationIdentity: request.RegistrationIdentity, OperationID: request.OperationID, KeyID: request.KeyID, RetentionNanos: request.RetentionNanos, RequestedEventID: requested.ID, RequestedSequence: requested.Sequence, RequestedAt: requested.Time, Creation: creation}
	activated := appendSource(t, log, request.KeyID, eventprivacy.EventActivated, creation.CreatedAt, activation)
	input := events.Event{ID: "guarded-private", Type: sourcePrivateType, TenantID: sourceTenant, Data: []byte(`{"email":"protected-private@example.invalid"}`), Actor: &events.Actor{Subject: "protected-private-actor"}}
	private, err := log.Append(t.Context(), input)
	if err != nil {
		t.Fatal(err)
	}
	if private.Protection == nil || !bytes.Equal(private.Data, input.Data) {
		t.Fatal("active policy did not preserve its protected logical view")
	}
	var stored []byte
	if err := log.ExportBackupHistoryThrough(t.Context(), private.Sequence, func(record events.BackupHistoryRecord) error {
		if record.Sequence == private.Sequence {
			stored = bytes.Clone(record.Stored)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(stored) == 0 || bytes.Contains(stored, []byte("protected-private")) {
		t.Fatal("immutable source retained readable protected fields")
	}
	var storedEnvelope struct {
		Schema     int                         `json:"v"`
		Data       []byte                      `json:"data"`
		Actor      *events.Actor               `json:"actor"`
		Protection *eventspec.ProtectedPayload `json:"protection"`
	}
	if err := json.Unmarshal(stored, &storedEnvelope); err != nil {
		t.Fatal(err)
	}
	if storedEnvelope.Schema >= 0 || storedEnvelope.Actor != nil || storedEnvelope.Protection == nil || json.Valid(storedEnvelope.Data) || bytes.Contains(storedEnvelope.Data, []byte("protected-private")) {
		t.Fatal("stored source exposed a readable base64 payload or actor")
	}
	time.Sleep(150 * time.Millisecond)
	again, err := log.Append(t.Context(), input)
	if err != nil || again.Sequence != private.Sequence {
		t.Fatalf("guarded private retry minted another source: %v", err)
	}
	activationWire, err := json.Marshal(activation)
	if err != nil {
		t.Fatal(err)
	}
	again, err = log.Append(t.Context(), events.Event{ID: activated.ID, Type: activated.Type, TenantID: sourceTenant, Time: activated.Time, SchemaVersion: 1, Data: activationWire})
	if err != nil || again.Sequence != activated.Sequence {
		t.Fatalf("public control retry duplicated after broker dedup: %v", err)
	}
	appendSource(t, log, "guarded-offboard", "tenant.offboarded", time.Now().UTC(), struct {
		RowsDeleted int `json:"rows_deleted"`
	}{0})
	lifetime, err := reader.Policy.LatestLifetime(t.Context(), sourceTenant)
	if err != nil {
		t.Fatal(err)
	}
	authorizer.want, err = eventprivacy.NewDestructionRequest(lifetime)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := keys.Destroy(t.Context(), authorizer.want)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := eventprotect.VerifyDestructionReceipt(key.JWKS(), receipt)
	if err != nil {
		t.Fatal(err)
	}
	appendSource(t, log, "guarded-completed", eventprivacy.EventDestroyed, claims.RemovedAt, eventprivacy.Destroyed{JWS: receipt})
	erased, found, err := log.EventByID(t.Context(), private.ID)
	if err != nil || !found || !erased.SensitiveErased || erased.Data != nil || erased.Actor != nil {
		t.Fatalf("verified destruction did not erase the logical view: %v", err)
	}
	if err := log.ExportBackupHistoryThrough(t.Context(), private.Sequence, func(record events.BackupHistoryRecord) error {
		if record.Sequence == private.Sequence && !bytes.Equal(record.Stored, stored) {
			t.Fatal("destruction rewrote immutable ciphertext")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	old, found, err := log.EventByID(t.Context(), legacy.ID)
	if err != nil || !found || old.SensitiveErased || !bytes.Equal(old.Data, legacy.Data) {
		t.Fatalf("pre-feature bytes changed: %v", err)
	}
}
