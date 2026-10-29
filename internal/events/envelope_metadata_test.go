// SPDX-License-Identifier: BUSL-1.1

package events

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/nats-io/nats.go/jetstream"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/eventprotect"
)

type forbiddenMetadataKeyAccess struct{ calls int }

func (k *forbiddenMetadataKeyAccess) WithKey(context.Context, eventprotect.KeyRef, func(seal.KeyWrapper) error) error {
	k.calls++
	return errors.New("metadata must not open keys")
}

func TestMetadataReadNeedsNoCustodian(t *testing.T) {
	log, _, _ := protectedStorageFixture(t)
	input := Event{ID: "metadata-protected", Type: protectedStorageTestType, TenantID: "d59b4292-1adc-4d43-a405-781f95b1779c", Data: []byte(`{"email":"private@example.invalid"}`), Actor: &Actor{Subject: "private actor"}}
	appended, err := log.Append(t.Context(), input)
	if err != nil {
		t.Fatal(err)
	}
	forbidden := &forbiddenMetadataKeyAccess{}
	log.eventProtection.Keys = forbidden
	var result []EnvelopeMetadata
	if err := log.ReplayTenantMetadataTypesThrough(t.Context(), input.TenantID, 1, appended.Sequence, []string{input.Type}, func(meta EnvelopeMetadata) error { result = append(result, meta); return nil }); err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 || result[0].ID != input.ID || result[0].Sequence != appended.Sequence || result[0].DeclaredKeyID != appended.Protection.KeyID || forbidden.calls != 0 {
		t.Fatal("metadata opened custody or changed source identity")
	}
	if _, _, err := log.EventAtSequence(t.Context(), appended.Sequence); err == nil || forbidden.calls != 1 {
		t.Fatal("logical protected read bypassed custody")
	}
}

func TestMetadataViewCannotCarryBodies(t *testing.T) {
	typ := reflect.TypeOf(EnvelopeMetadata{})
	for _, field := range []string{"Data", "Actor", "Protection", "Ciphertext"} {
		if _, exists := typ.FieldByName(field); exists {
			t.Fatalf("metadata includes private body field %s", field)
		}
	}
}

func TestMetadataRecoversTransferredProtectedSourceWithoutCustodian(t *testing.T) {
	source, _, _ := protectedStorageFixture(t)
	event, err := source.Append(t.Context(), Event{ID: "metadata-transfer", TenantID: "d59b4292-1adc-4d43-a405-781f95b1779c", Type: protectedStorageTestType, Data: []byte(`{"email":"private@example.invalid"}`)})
	if err != nil {
		t.Fatal(err)
	}
	var records []BackupHistoryRecord
	if err := source.ExportBackupHistoryThrough(t.Context(), event.Sequence, func(record BackupHistoryRecord) error { records = append(records, record); return nil }); err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 {
		t.Fatal("fixture must contain one retained source event")
	}
	cfg := config.NATS{Mode: config.NATSEmbedded, StoreDir: filepath.Join(t.TempDir(), "restored")}
	target, err := Open(t.Context(), cfg, WithRequiredPrivacyEventPolicies())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = target.Close() })
	// Exact source transfer is a storage seam, not the full authenticated
	// PostgreSQL/snapshot/offboard recovery workflow.
	if _, err := target.RestoreBackupHistory(t.Context(), event.Sequence, crypto.SHA256Hex(records[0].Stored), func(yield func(BackupHistoryRecord) error) error { return yield(records[0]) }); err != nil {
		t.Fatal(err)
	}
	if err := target.Close(); err != nil {
		t.Fatal(err)
	}
	target, err = Open(t.Context(), cfg, WithRequiredPrivacyEventPolicies())
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	if err := target.ReplayTenantMetadataTypesThrough(t.Context(), event.TenantID, 1, event.Sequence, []string{event.Type}, func(meta EnvelopeMetadata) error {
		if meta.ID != event.ID || meta.DeclaredKeyID != event.Protection.KeyID {
			t.Fatal("cold metadata lost protected source identity")
		}
		count++
		return nil
	}); err != nil || count != 1 {
		t.Fatalf("cold metadata without custody: count=%d err=%v", count, err)
	}
	if _, _, err := target.EventAtSequence(t.Context(), event.Sequence); !errors.Is(err, ErrEventProtectionUnavailable) {
		t.Fatalf("logical read bypassed missing custody: %v", err)
	}
}

func TestMetadataIndexRejectsFalsePointers(t *testing.T) {
	for _, mode := range []string{"digest", "tenant", "type"} {
		t.Run(mode, func(t *testing.T) {
			log, _, _ := protectedStorageFixture(t)
			tenant := "d59b4292-1adc-4d43-a405-781f95b1779c"
			sourceTenant := tenant
			selectedType := protectedStorageTestType
			if mode == "tenant" {
				sourceTenant = "2c14fe81-1956-4e9d-a174-e27a38e8e979"
			}
			if mode == "type" {
				selectedType = "tenant.registered"
			}
			event, err := log.Append(t.Context(), Event{ID: "metadata-pointer", Type: protectedStorageTestType, TenantID: sourceTenant, Data: []byte(`{"email":"a@example.invalid"}`)})
			if err != nil {
				t.Fatal(err)
			}
			if err := log.warmTenantIndex(t.Context()); err != nil {
				t.Fatal(err)
			}
			state, err := log.schedulerSafetySnapshot(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			index, epoch, err := log.tenantIndexFor(t.Context(), state)
			if err != nil {
				t.Fatal(err)
			}
			// Start a deliberately corrupt derivative index from a retained
			// source event. The source itself is never changed.
			if err := log.js.DeleteStream(t.Context(), index.CachedInfo().Config.Name); err != nil {
				t.Fatal(err)
			}
			if _, _, err := log.tenantIndexFor(t.Context(), state); err != nil {
				t.Fatal(err)
			}
			_, source, err := log.resolveActiveStream(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			raw, err := source.GetMsg(t.Context(), event.Sequence)
			if err != nil {
				t.Fatal(err)
			}
			digest := crypto.SHA256Hex(raw.Data)
			if mode == "digest" {
				digest = strings.Repeat("0", 64)
			}
			wire, err := json.Marshal(tenantIndexEntry{SourceSequence: event.Sequence, Digest: digest})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := log.js.Publish(t.Context(), tenantIndexTypedEventSubject(epoch, tenant, selectedType), wire); err != nil {
				t.Fatal(err)
			}
			visits := 0
			if err := log.ReplayTenantMetadataTypesThrough(t.Context(), tenant, 1, event.Sequence, []string{selectedType}, func(EnvelopeMetadata) error { visits++; return nil }); err == nil || visits != 0 {
				t.Fatalf("false %s pointer accepted: %v, visits=%d", mode, err, visits)
			}
		})
	}
}

func TestMetadataTypesKeepSourceOrderRangeAndColdRecovery(t *testing.T) {
	cfg := config.NATS{Mode: config.NATSEmbedded, StoreDir: filepath.Join(t.TempDir(), "nats")}
	log, err := Open(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	for i, item := range []struct{ tenant, kind string }{
		{"a", "tenant.registered"}, {"b", "tenant.registered"},
		{"a", "tenant.renamed"}, {"a", "tenant.offboarded"},
		{"a", "tenant.registered"},
	} {
		if _, err := log.Append(t.Context(), Event{ID: string(rune('a' + i)), TenantID: item.tenant, Type: item.kind, Data: []byte(`{}`)}); err != nil {
			t.Fatal(err)
		}
	}
	read := func(log *Log) {
		t.Helper()
		var sequences []uint64
		if err := log.ReplayTenantMetadataTypesThrough(t.Context(), "a", 3, 4, []string{"tenant.registered", "tenant.offboarded", "tenant.offboarded"}, func(meta EnvelopeMetadata) error { sequences = append(sequences, meta.Sequence); return nil }); err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(sequences, []uint64{4}) {
			t.Fatalf("finite typed range=%v", sequences)
		}
	}
	read(log)
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	log, err = Open(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	read(log)
	want := errors.New("visitor refuses")
	if err := log.ReplayTenantMetadataTypesThrough(t.Context(), "a", 1, 5, []string{"tenant.registered"}, func(EnvelopeMetadata) error { return want }); !errors.Is(err, want) {
		t.Fatalf("visitor error=%v", err)
	}
	for _, types := range [][]string{{""}, {"tenant.*"}, make([]string, 17)} {
		if err := log.ReplayTenantMetadataTypesThrough(t.Context(), "a", 1, 5, types, func(EnvelopeMetadata) error { return nil }); err == nil {
			t.Fatal("unbounded/invalid type scope accepted")
		}
	}
	if err := log.ReplayTenantMetadataTypesThrough(t.Context(), "a", 1, 6, []string{"tenant.registered"}, func(EnvelopeMetadata) error { return nil }); err == nil {
		t.Fatal("cut beyond source head accepted")
	}
}

func TestMetadataIndexUpgradePreservesSourceAndRebuildsPointers(t *testing.T) {
	cfg := config.NATS{Mode: config.NATSEmbedded, StoreDir: filepath.Join(t.TempDir(), "nats")}
	log, err := Open(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	event, err := log.Append(t.Context(), Event{TenantID: "a", Type: "tenant.registered", Data: []byte(`{"name":"legacy"}`)})
	if err != nil {
		t.Fatal(err)
	}
	state, err := log.schedulerSafetySnapshot(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	epoch := eventIDSourceEpoch(state)
	oldName := "TRSTCTL_TENANT_EVENTS_" + epoch
	oldSubject := "trstctl_tenant_events." + epoch
	if _, err := log.js.CreateStream(t.Context(), jetstream.StreamConfig{Name: oldName, Subjects: []string{oldSubject + ".>"}, Storage: jetstream.FileStorage, Metadata: map[string]string{"trstctl.source_name": state.Name}}); err != nil {
		t.Fatal(err)
	}
	if _, err := log.js.Publish(t.Context(), oldSubject+".tenant."+crypto.SHA256Hex([]byte("a")), []byte(`{"source_sequence":1,"digest":"obsolete"}`)); err != nil {
		t.Fatal(err)
	}
	_, source, err := log.resolveActiveStream(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	before, err := source.GetMsg(t.Context(), event.Sequence)
	if err != nil {
		t.Fatal(err)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	log, err = Open(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	if err := log.ReplayTenantMetadataTypesThrough(t.Context(), "a", 1, event.Sequence, []string{event.Type}, func(EnvelopeMetadata) error { count++; return nil }); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("upgrade lost source event: %d", count)
	}
	if _, err := log.js.Stream(t.Context(), oldName); !errors.Is(err, jetstream.ErrStreamNotFound) {
		t.Fatalf("obsolete owned index not retired: %v", err)
	}
	_, source, err = log.resolveActiveStream(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	after, err := source.GetMsg(t.Context(), event.Sequence)
	if err != nil {
		t.Fatal(err)
	}
	if string(before.Data) != string(after.Data) {
		t.Fatal("index upgrade changed original source bytes")
	}
}
