// SPDX-License-Identifier: MPL-2.0

package events

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"testing"

	"trstctl.com/trstctl/internal/config"
)

func TestTenantKeyDomainRewriteSecurelyReplacesOnlyTargetTenantData(t *testing.T) {
	ctx := context.Background()
	const (
		targetTenant = "11111111-1111-1111-1111-111111111111"
		otherTenant  = "22222222-2222-2222-2222-222222222222"
	)
	log, err := Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatalf("Open embedded: %v", err)
	}
	t.Cleanup(func() { _ = log.Close() })

	target, err := log.Append(ctx, Event{
		ID: "target-event", Type: "secret.version.written", TenantID: targetTenant,
		Data: []byte(`{"sealed":"deployment-ciphertext"}`),
	})
	if err != nil {
		t.Fatalf("Append target: %v", err)
	}
	other, err := log.Append(ctx, Event{
		ID: "other-event", Type: "secret.version.written", TenantID: otherTenant,
		Data: []byte(`{"sealed":"other-tenant-ciphertext"}`),
	})
	if err != nil {
		t.Fatalf("Append other: %v", err)
	}

	changed, err := log.RewriteTenantData(ctx, targetTenant, func(eventType string, schemaVersion int, data []byte) ([]byte, bool, error) {
		if eventType != "secret.version.written" {
			return nil, false, errors.New("unexpected event type")
		}
		if schemaVersion != DefaultSchemaVersion {
			return nil, false, errors.New("unexpected schema version")
		}
		return bytes.ReplaceAll(data, []byte("deployment-ciphertext"), []byte("tenant-domain-ciphertext")), true, nil
	})
	if err != nil {
		t.Fatalf("RewriteTenantData: %v", err)
	}
	if changed != 1 {
		t.Fatalf("RewriteTenantData changed %d events, want 1", changed)
	}
	raw := rawStreamBytes(t, log)
	if bytes.Contains(raw, []byte(base64.StdEncoding.EncodeToString([]byte(`{"sealed":"deployment-ciphertext"}`)))) {
		t.Fatalf("raw hot log retains target deployment ciphertext: %s", raw)
	}
	if !bytes.Contains(raw, []byte(base64.StdEncoding.EncodeToString([]byte(`{"sealed":"tenant-domain-ciphertext"}`)))) ||
		!bytes.Contains(raw, []byte(base64.StdEncoding.EncodeToString([]byte(`{"sealed":"other-tenant-ciphertext"}`)))) {
		t.Fatalf("raw hot log lost replacement or other tenant bytes: %s", raw)
	}

	var replayed []Event
	if err := log.Replay(ctx, 0, func(ev Event) error {
		replayed = append(replayed, ev)
		return nil
	}); err != nil {
		t.Fatalf("Replay: %v", err)
	}
	if len(replayed) != 2 {
		t.Fatalf("Replay returned %d events, want 2", len(replayed))
	}
	if replayed[0].ID != target.ID || replayed[0].Time != target.Time ||
		replayed[0].Type != target.Type || replayed[0].TenantID != target.TenantID {
		t.Fatalf("target event envelope changed: got %+v want %+v", replayed[0], target)
	}
	if replayed[1].ID != other.ID || !bytes.Equal(replayed[1].Data, other.Data) {
		t.Fatalf("other tenant event changed: got %+v want %+v", replayed[1], other)
	}
}

func TestTenantKeyDomainRewriteFailureLeavesHotLogUntouched(t *testing.T) {
	ctx := context.Background()
	const tenantID = "11111111-1111-1111-1111-111111111111"
	log, err := Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatalf("Open embedded: %v", err)
	}
	t.Cleanup(func() { _ = log.Close() })

	if _, err := log.Append(ctx, Event{
		Type: "secret.version.written", TenantID: tenantID,
		Data: []byte(`{"sealed":"first-deployment-ciphertext"}`),
	}); err != nil {
		t.Fatalf("Append first: %v", err)
	}
	if _, err := log.Append(ctx, Event{
		Type: "secret.version.written", TenantID: tenantID,
		Data: []byte(`{"sealed":"second-deployment-ciphertext"}`),
	}); err != nil {
		t.Fatalf("Append second: %v", err)
	}
	before := rawStreamBytes(t, log)
	calls := 0
	changed, err := log.RewriteTenantData(ctx, tenantID, func(_ string, _ int, data []byte) ([]byte, bool, error) {
		calls++
		if calls == 2 {
			return nil, false, errors.New("synthetic rewrap failure")
		}
		return bytes.ReplaceAll(data, []byte("deployment"), []byte("tenant")), true, nil
	})
	if err == nil {
		t.Fatal("RewriteTenantData succeeded despite transform failure")
	}
	if changed != 0 {
		t.Fatalf("RewriteTenantData changed count = %d after abort, want 0", changed)
	}
	after := rawStreamBytes(t, log)
	if !bytes.Equal(after, before) {
		t.Fatalf("hot log changed after preflight failure:\nbefore=%s\nafter=%s", before, after)
	}
}

func TestTenantKeyDomainRewriteRejectsMissingScopeOrTransform(t *testing.T) {
	log := &Log{}
	if _, err := log.RewriteTenantData(context.Background(), "", func(string, int, []byte) ([]byte, bool, error) {
		return nil, false, nil
	}); err == nil {
		t.Fatal("RewriteTenantData accepted empty tenant")
	}
	if _, err := log.RewriteTenantData(context.Background(), "tenant", nil); err == nil {
		t.Fatal("RewriteTenantData accepted nil transform")
	}
}
