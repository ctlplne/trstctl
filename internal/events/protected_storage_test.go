// SPDX-License-Identifier: BUSL-1.1

package events

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/eventprotect"
)

const protectedStorageTestType = "a233.protected_storage"

func init() {
	if err := RegisterPrivacyEventPolicy(protectedStorageTestType, 1, PrivacyEventPolicy{
		Rules: []PrivacyFieldRule{{Path: "/email", Mode: PrivacyFieldIdentityExact}},
		PayloadShape: PrivacyPayloadShapeOf[struct {
			Email string `json:"email"`
		}](),
	}); err != nil {
		panic(err)
	}
}

// The integration test uses the actual file authority and crypto codec. This
// admission fixture only chooses when protection starts; production must bind
// that choice to retained activation events and the tenant lifecycle fence.
type storageProtectionAdmission struct {
	mu     sync.Mutex
	active map[string]eventprotect.KeyRef
}

func (a *storageProtectionAdmission) WithTenantEventProtection(ctx context.Context, _ string, fn func(context.Context) error) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return fn(ctx)
}

func (a *storageProtectionAdmission) EventProtectionFor(_ context.Context, event Event) (EventProtectionDecision, error) {
	ref, found := a.active[event.TenantID]
	if !found {
		return EventProtectionDecision{Mode: EventProtectionLegacy}, nil
	}
	return EventProtectionDecision{Mode: EventProtectionSensitive, Ref: ref}, nil
}

type storageKeyLocker struct{}

func (storageKeyLocker) WithKeyLock(ctx context.Context, _ eventprotect.KeyRef, fn func(context.Context) error) error {
	return fn(ctx)
}

func protectedStorageFixture(t *testing.T) (*Log, EventProtection, *storageProtectionAdmission) {
	t.Helper()
	base := t.TempDir()
	keys, err := eventprotect.NewFileAuthority(eventprotect.FileAuthorityConfig{
		Directory: filepath.Join(base, "independent-keys"), BackupRoots: []string{filepath.Join(base, "events")}, Locker: storageKeyLocker{},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = keys.Close() })
	ref := eventprotect.KeyRef{TenantID: "d59b4292-1adc-4d43-a405-781f95b1779c", ID: "02f0b795-3f17-46a9-a9cc-a7bdd7ee21eb"}
	if err := keys.Provision(t.Context(), ref); err != nil {
		t.Fatal(err)
	}
	admission := &storageProtectionAdmission{active: map[string]eventprotect.KeyRef{ref.TenantID: ref}}
	protection := EventProtection{Keys: keys, Admission: admission}
	log, err := Open(t.Context(), config.NATS{Mode: config.NATSEmbedded, StoreDir: filepath.Join(base, "events")},
		WithRequiredPrivacyEventPolicies(), WithEventProtection(protection), WithDuplicateWindowForTesting(100*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	return log, protection, admission
}

func TestProtectedAppendKeepsReadableViewsAndExactCiphertextSource(t *testing.T) {
	log, _, _ := protectedStorageFixture(t)
	input := Event{ID: "a233-exact-source", Type: protectedStorageTestType,
		TenantID: "d59b4292-1adc-4d43-a405-781f95b1779c",
		Data:     []byte(" { \"email\" : \"a233-private-marker@example.invalid\" }\n"),
		Actor:    &Actor{Subject: "a233-private-actor", Roles: []string{"operator"}},
	}
	appended, err := log.Append(t.Context(), input)
	if err != nil {
		t.Fatal(err)
	}
	if appended.Protection == nil || !bytes.Equal(appended.Data, input.Data) || !reflect.DeepEqual(appended.Actor, input.Actor) {
		t.Fatal("append lost the exact readable command or its immutable protection envelope")
	}
	_, stream, err := log.resolveActiveStream(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	raw, err := stream.GetMsg(t.Context(), appended.Sequence)
	if err != nil {
		t.Fatal(err)
	}
	for _, private := range [][]byte{[]byte("a233-private-marker"), []byte("a233-private-actor"), input.Data} {
		if bytes.Contains(raw.Data, private) {
			t.Fatal("private bytes remained in the raw source envelope")
		}
	}
	var oldReader struct {
		SchemaVersion int    `json:"v"`
		Data          []byte `json:"data"`
	}
	if err := json.Unmarshal(raw.Data, &oldReader); err != nil {
		t.Fatal(err)
	}
	if oldReader.SchemaVersion > 0 || json.Valid(oldReader.Data) {
		t.Fatal("an old reader could mistake protected source for a valid legacy payload")
	}
	byID, found, err := log.EventByID(t.Context(), input.ID)
	if err != nil || !found || !bytes.Equal(byID.Data, input.Data) || !reflect.DeepEqual(byID.Protection, appended.Protection) {
		t.Fatalf("logical ID lookup: %v", err)
	}
	bySequence, found, err := log.EventAtSequence(t.Context(), appended.Sequence)
	if err != nil || !found || !bytes.Equal(bySequence.Data, input.Data) {
		t.Fatalf("logical sequence lookup: %v", err)
	}
	check := func(e Event) error {
		if !bytes.Equal(e.Data, input.Data) || !reflect.DeepEqual(e.Actor, input.Actor) || e.Protection == nil {
			t.Fatal("replay returned ciphertext or changed source bytes as domain data")
		}
		return nil
	}
	if err := log.Replay(t.Context(), 1, check); err != nil {
		t.Fatal(err)
	}
	if err := log.ReplayTenantThrough(t.Context(), input.TenantID, 1, appended.Sequence, check); err != nil {
		t.Fatal(err)
	}
	if err := log.ReplayTenantTypesThrough(t.Context(), input.TenantID, 1, appended.Sequence, []string{input.Type}, check); err != nil {
		t.Fatal(err)
	}
	var backup []BackupHistoryRecord
	if err := log.ExportBackupHistoryThrough(t.Context(), appended.Sequence, func(record BackupHistoryRecord) error { backup = append(backup, record); return nil }); err != nil {
		t.Fatal(err)
	}
	if len(backup) != 1 || !bytes.Equal(backup[0].Stored, raw.Data) {
		t.Fatal("source backup changed or opened the immutable ciphertext")
	}
}

func TestProtectedAppendRecoversCiphertextBeyondBrokerDuplicateWindow(t *testing.T) {
	log, _, _ := protectedStorageFixture(t)
	input := Event{ID: "a233-after-dedup", Type: protectedStorageTestType, TenantID: "d59b4292-1adc-4d43-a405-781f95b1779c", Data: []byte(`{"email":"retry@example.invalid"}`)}
	first, err := log.Append(t.Context(), input)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(150 * time.Millisecond)
	again, err := log.Append(t.Context(), input)
	if err != nil || again.Sequence != first.Sequence || !reflect.DeepEqual(again.Protection, first.Protection) {
		t.Fatalf("durable retry created another ciphertext: %v", err)
	}
	if head, err := log.LastSequence(t.Context()); err != nil || head != first.Sequence {
		t.Fatalf("durable retry advanced the log: %d %v", head, err)
	}
	input.Data = []byte(`{"email":"changed@example.invalid"}`)
	if _, err := log.Append(t.Context(), input); !errors.Is(err, ErrConflictingEventIdentity) {
		t.Fatalf("event ID admitted a changed protected command: %v", err)
	}
}

func TestProtectedSourceNeedsCustodyButLegacySourceDoesNot(t *testing.T) {
	log, _, _ := protectedStorageFixture(t)
	input := Event{ID: "a233-legacy-source", Type: protectedStorageTestType, TenantID: "2c14fe81-1956-4e9d-a174-e27a38e8e979", Data: []byte(`{"email":"legacy@example.invalid"}`)}
	legacy, err := log.Append(t.Context(), input)
	if err != nil || legacy.Protection != nil {
		t.Fatalf("unopted tenant changed: %v", err)
	}
	input.ID, input.TenantID = "a233-needs-custody", "d59b4292-1adc-4d43-a405-781f95b1779c"
	protected, err := log.Append(t.Context(), input)
	if err != nil {
		t.Fatal(err)
	}
	log.eventProtection = nil
	if _, _, err := log.EventAtSequence(t.Context(), protected.Sequence); !errors.Is(err, ErrEventProtectionUnavailable) {
		t.Fatalf("missing custodian silently served protected data: %v", err)
	}
	if e, found, err := log.EventAtSequence(t.Context(), legacy.Sequence); err != nil || !found || !bytes.Equal(e.Data, legacy.Data) {
		t.Fatalf("legacy read acquired a new key dependency: %v", err)
	}
}

func TestProtectedIdentityCannotEscapeToUnprotectedTenant(t *testing.T) {
	for _, elapsed := range []time.Duration{0, 150 * time.Millisecond} {
		t.Run(elapsed.String(), func(t *testing.T) {
			log, _, _ := protectedStorageFixture(t)
			input := Event{ID: "a233-cross-tenant-id", Type: protectedStorageTestType, TenantID: "d59b4292-1adc-4d43-a405-781f95b1779c", Data: []byte(`{"email":"first@example.invalid"}`)}
			first, err := log.Append(t.Context(), input)
			if err != nil {
				t.Fatal(err)
			}
			time.Sleep(elapsed)
			input.TenantID, input.Data = "2c14fe81-1956-4e9d-a174-e27a38e8e979", []byte(`{"email":"foreign@example.invalid"}`)
			if returned, err := log.Append(t.Context(), input); !errors.Is(err, ErrConflictingEventIdentity) || len(returned.Data) != 0 {
				t.Fatalf("unprotected tenant recovered or replaced a protected identity: %v", err)
			}
			if head, err := log.LastSequence(t.Context()); err != nil || head != first.Sequence {
				t.Fatalf("foreign retry changed source history: %d %v", head, err)
			}
		})
	}
}

func TestProtectedStoredEnvelopeRejectsAmbiguousPublicFraming(t *testing.T) {
	log, _, _ := protectedStorageFixture(t)
	input := Event{ID: "a233-closed-wire", Type: protectedStorageTestType, TenantID: "d59b4292-1adc-4d43-a405-781f95b1779c", Data: []byte(`{"email":"first@example.invalid"}`)}
	appended, err := log.Append(t.Context(), input)
	if err != nil {
		t.Fatal(err)
	}
	_, stream, err := log.resolveActiveStream(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	raw, err := stream.GetMsg(t.Context(), appended.Sequence)
	if err != nil {
		t.Fatal(err)
	}
	for name, changed := range map[string][]byte{
		"unknown":              append([]byte(`{"unknown":"extra plaintext",`), raw.Data[1:]...),
		"duplicate":            append([]byte(`{"id":"shadow",`), raw.Data[1:]...),
		"alternate whitespace": append([]byte(" "), raw.Data...),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeStored(changed, appended.Sequence); err == nil {
				t.Fatal("protected framing had an alternative unsigned interpretation")
			}
		})
	}
}

func TestProtectedRetainedIdentityIncludesCiphertextAfterErasure(t *testing.T) {
	left := Event{ID: "same", Type: protectedStorageTestType, TenantID: "tenant", SensitiveErased: true}
	left.Protection = &eventprotect.Envelope{Version: 1, KeyID: "key", PolicyDigest: "policy", Ciphertext: []byte("original")}
	right := left
	changed := *left.Protection
	changed.Ciphertext = []byte("different")
	right.Protection = &changed
	if sameRetainedEvent(left, right) {
		t.Fatal("erased readable views hid conflicting ciphertext identities")
	}
}

func TestProtectedReplayLookupOwnsItsImmutableEnvelope(t *testing.T) {
	log, _, _ := protectedStorageFixture(t)
	input := Event{ID: "a233-lookup-owned", Type: protectedStorageTestType, TenantID: "d59b4292-1adc-4d43-a405-781f95b1779c", Data: []byte(`{"email":"first@example.invalid"}`)}
	appended, err := log.Append(t.Context(), input)
	if err != nil {
		t.Fatal(err)
	}
	got, found, err := log.ReplayThroughAndLookup(t.Context(), 1, appended.Sequence, appended.ID, func(event Event) error {
		event.Protection.Ciphertext[0] ^= 0xff
		event.Protection.PolicyDigest = "mutated callback view"
		return nil
	})
	if err != nil || !found || !reflect.DeepEqual(got.Protection, appended.Protection) {
		t.Fatalf("callback mutated retained lookup authority: %v", err)
	}
}

func TestProtectedSourceExactHistoryTransferRetainsCiphertext(t *testing.T) {
	source, protection, _ := protectedStorageFixture(t)
	input := Event{ID: "a233-history-transfer", Type: protectedStorageTestType, TenantID: "d59b4292-1adc-4d43-a405-781f95b1779c", Data: []byte(`{"email":"transfer@example.invalid"}`)}
	appended, err := source.Append(t.Context(), input)
	if err != nil {
		t.Fatal(err)
	}
	var records []BackupHistoryRecord
	if err := source.ExportBackupHistoryThrough(t.Context(), appended.Sequence, func(record BackupHistoryRecord) error {
		records = append(records, record)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 {
		t.Fatal("fixture source must have exactly one retained record")
	}
	target, err := Open(t.Context(), config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()}, WithRequiredPrivacyEventPolicies(), WithEventProtection(protection))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = target.Close() })
	// This is the exact event-history transfer seam. It does not claim the full
	// authenticated PostgreSQL/snapshot/offboard restore workflow is built.
	if _, err := target.RestoreBackupHistory(t.Context(), appended.Sequence, crypto.SHA256Hex(records[0].Stored), func(yield func(BackupHistoryRecord) error) error {
		for _, record := range records {
			if err := yield(record); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	got, found, err := target.EventAtSequence(t.Context(), appended.Sequence)
	if err != nil || !found || !bytes.Equal(got.Data, input.Data) || !reflect.DeepEqual(got.Protection, appended.Protection) {
		t.Fatalf("transferred source did not open with its independent custodian: %v", err)
	}
	if err := target.ExportBackupHistoryThrough(t.Context(), appended.Sequence, func(record BackupHistoryRecord) error {
		if len(records) != 1 || !bytes.Equal(record.Stored, records[0].Stored) {
			t.Fatal("history transfer re-encrypted or opened stored source")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestProtectedRetryUsesTheStoredActorEncoding(t *testing.T) {
	log, _, _ := protectedStorageFixture(t)
	input := Event{ID: "a233-empty-actor-roles", Type: protectedStorageTestType, TenantID: "d59b4292-1adc-4d43-a405-781f95b1779c", Data: []byte(`{"email":"first@example.invalid"}`), Actor: &Actor{Subject: "actor", Roles: []string{}}}
	first, err := log.Append(t.Context(), input)
	if err != nil {
		t.Fatal(err)
	}
	if again, err := log.Append(t.Context(), input); err != nil || again.Sequence != first.Sequence {
		t.Fatalf("the actor's omitted empty roles made an identical retry conflict: %v", err)
	}
}
