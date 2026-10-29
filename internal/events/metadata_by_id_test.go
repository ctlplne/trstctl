// SPDX-License-Identifier: BUSL-1.1

package events

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nats-io/nats.go/jetstream"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
)

func TestTenantMetadataByIDDoesNotOpenProtectedBodies(t *testing.T) {
	log, _, _ := protectedStorageFixture(t)
	event, err := log.Append(t.Context(), Event{ID: "protected-metadata-id", TenantID: "d59b4292-1adc-4d43-a405-781f95b1779c", Type: protectedStorageTestType, Data: []byte(`{"email":"metadata-private@example.invalid"}`), Actor: &Actor{Subject: "metadata-private-actor"}})
	if err != nil {
		t.Fatal(err)
	}
	forbidden := &forbiddenMetadataKeyAccess{}
	log.eventProtection.Keys = forbidden
	meta, found, err := log.TenantMetadataByID(t.Context(), event.TenantID, event.ID)
	if err != nil || !found || meta.ID != event.ID || meta.Sequence != event.Sequence || meta.DeclaredKeyID != event.Protection.KeyID || forbidden.calls != 0 {
		t.Fatalf("metadata opened custody or changed source identity: found=%v err=%v calls=%d", found, err, forbidden.calls)
	}
	if alias, found, err := log.TenantMetadataByID(t.Context(), strings.ToUpper(event.TenantID), event.ID); err != nil || !found || alias.ID != event.ID || forbidden.calls != 0 {
		t.Fatalf("tenant UUID alias lost source identity: found=%v err=%v", found, err)
	}
	if _, _, err := log.TenantMetadataByID(t.Context(), "2c14fe81-1956-4e9d-a174-e27a38e8e979", event.ID); !errors.Is(err, ErrConflictingEventIdentity) || forbidden.calls != 0 {
		t.Fatalf("foreign metadata source was accepted/opened: %v calls=%d", err, forbidden.calls)
	}
	if _, found, err := log.TenantMetadataByID(t.Context(), event.TenantID, "absent-metadata-id"); err != nil || found {
		t.Fatalf("absent identity invented metadata: found=%v err=%v", found, err)
	}
	if _, _, err := log.EventByID(t.Context(), event.ID); err == nil || forbidden.calls != 1 {
		t.Fatal("fixture logical read did not enforce its unavailable custodian")
	}
}

func TestMetadataUUIDScopeRebuildsLegacyCaseSensitiveIndex(t *testing.T) {
	tenant := "d59b4292-1adc-4d43-a405-781f95b1779c"
	spelling := strings.ToUpper(tenant)
	cfg := config.NATS{Mode: config.NATSEmbedded, StoreDir: filepath.Join(t.TempDir(), "nats")}
	log, err := Open(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	event, err := log.Append(t.Context(), Event{ID: "legacy-uppercase-tenant", TenantID: spelling, Type: "tenant.registered", Data: []byte(`{"name":"legacy"}`)})
	if err != nil {
		t.Fatal(err)
	}
	state, err := log.schedulerSafetySnapshot(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	epoch := eventIDSourceEpoch(state)
	_, source, err := log.resolveActiveStream(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	before, err := source.GetMsg(t.Context(), event.Sequence)
	if err != nil {
		t.Fatal(err)
	}
	oldName := "TRSTCTL_TENANT_EVENTS_V2_" + epoch
	oldRoot := "trstctl_tenant_events_v2." + epoch
	if _, err := log.js.CreateStream(t.Context(), jetstream.StreamConfig{Name: oldName, Subjects: []string{oldRoot + ".>"}, Storage: jetstream.FileStorage, Metadata: map[string]string{"trstctl.source_name": state.Name}}); err != nil {
		t.Fatal(err)
	}
	pointer, err := json.Marshal(tenantIndexEntry{SourceSequence: event.Sequence, Digest: crypto.SHA256Hex(before.Data)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := log.js.Publish(t.Context(), oldRoot+".tenant."+crypto.SHA256Hex([]byte(spelling))+".type."+crypto.SHA256Hex([]byte(event.Type)), pointer); err != nil {
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
	if err := log.ReplayTenantMetadataTypesThrough(t.Context(), tenant, 1, event.Sequence, []string{event.Type}, func(meta EnvelopeMetadata) error {
		if meta.ID != event.ID || meta.TenantID != tenant {
			t.Fatal("legacy tenant spelling escaped canonical routing scope")
		}
		count++
		return nil
	}); err != nil || count != 1 {
		t.Fatalf("canonical scope missed retained legacy source: count=%d err=%v", count, err)
	}
	if _, err := log.js.Stream(t.Context(), oldName); !errors.Is(err, jetstream.ErrStreamNotFound) {
		t.Fatalf("case-sensitive derived index was not retired: %v", err)
	}
	if err := log.ReplayTenantThrough(t.Context(), tenant, 1, event.Sequence, func(retained Event) error {
		if retained.TenantID != spelling {
			t.Fatal("logical routing rewrote original source header")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	_, source, err = log.resolveActiveStream(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	after, err := source.GetMsg(t.Context(), event.Sequence)
	if err != nil || string(before.Data) != string(after.Data) {
		t.Fatalf("scope upgrade changed immutable source: %v", err)
	}
}
