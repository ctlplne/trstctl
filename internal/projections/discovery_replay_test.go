// SPDX-License-Identifier: MPL-2.0

package projections_test

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/discovery"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

const (
	aud96SourceID        = "00000000-0000-4000-8000-000000009601"
	aud96RunID           = "00000000-0000-4000-8000-000000009602"
	aud96EarlierFinding  = "00000000-0000-4000-8000-000000009603"
	aud96LaterFinding    = "00000000-0000-4000-8000-000000009604"
	aud96ConflictingFind = "00000000-0000-4000-8000-000000009605"
	aud101EarlierSSH     = "00000000-0000-4000-8000-000000010101"
	aud101LaterSSH       = "00000000-0000-4000-8000-000000010102"
)

func TestDiscoveryFindingReplayCanonicalizesLegacyDuplicateAndPreservesTriageAUD96(t *testing.T) {
	s := newStore(t)
	log := openLog(t)
	ctx := context.Background()
	p := projections.New(s)

	appendAUD96DiscoveryBase(t, log)
	if err := p.ProjectCatchUp(ctx, log); err != nil {
		t.Fatalf("project discovery base: %v", err)
	}

	earlierAt := time.Date(2026, 8, 10, 7, 3, 10, 854841000, time.UTC)
	laterAt := earlierAt.Add(3 * time.Millisecond)
	mustAppendDiscoveryFindingAUD96(t, log, aud96EarlierFinding, earlierAt, 82, `{"action":"investigate","owner_hint":"security"}`)
	later := mustAppendDiscoveryFindingAUD96(t, log, aud96LaterFinding, laterAt, 82, `{"owner_hint":"security","action":"investigate"}`)

	// Reproduce the preserved deployment: an inline outbox receiver projected the
	// later duplicate before the durable checkpoint advanced past the earlier event.
	// A normal restart therefore replays earlier first into a row that currently has
	// later's payload ID.
	if err := p.Apply(ctx, later); err != nil {
		t.Fatalf("project out-of-order inline duplicate: %v", err)
	}
	before, err := s.GetDiscoveryFinding(ctx, tenantA, aud96LaterFinding)
	if err != nil {
		t.Fatalf("read pre-restart finding: %v", err)
	}
	if before.ID != aud96LaterFinding {
		t.Fatalf("pre-restart finding id = %q, want later id %q", before.ID, aud96LaterFinding)
	}

	mustAppend(t, log, events.Event{
		Type:     projections.EventDiscoveryFindingTriageChanged,
		TenantID: tenantA,
		Time:     laterAt.Add(time.Second),
		Data: mustJSONAUD96(t, projections.DiscoveryFindingTriageChanged{
			ID:     aud96LaterFinding,
			Status: string(discovery.TriageInvestigating),
			Actor:  "security@example.test",
			Reason: "review the shadow endpoint",
		}),
	})

	if err := p.ProjectCatchUp(ctx, log); err != nil {
		t.Fatalf("restart catch-up over legacy natural-key duplicate: %v; rows=%v", err, discoveryRowsAUD96(t, s))
	}
	got, err := s.GetDiscoveryFinding(ctx, tenantA, aud96EarlierFinding)
	if err != nil {
		t.Fatalf("read canonical finding after catch-up: %v", err)
	}
	if got.ID != aud96EarlierFinding {
		t.Fatalf("canonical id = %q, want earliest immutable event id %q", got.ID, aud96EarlierFinding)
	}
	if !got.DiscoveredAt.Equal(earlierAt) {
		t.Fatalf("canonical discovered_at = %s, want earliest event time %s", got.DiscoveredAt, earlierAt)
	}
	if got.TriageStatus != string(discovery.TriageInvestigating) || got.TriageActor != "security@example.test" {
		t.Fatalf("canonical triage = %q by %q, want investigating by security actor", got.TriageStatus, got.TriageActor)
	}
	// A durable triage event may name either legacy payload ID. Alias lookup must
	// still resolve to the one canonical finding after replay/rebuild.
	viaLegacyID, err := s.GetDiscoveryFinding(ctx, tenantA, aud96LaterFinding)
	if err != nil || viaLegacyID.ID != aud96EarlierFinding {
		t.Fatalf("legacy id lookup = %+v, err=%v; want canonical %q", viaLegacyID, err, aud96EarlierFinding)
	}

	warmRows := discoveryRowsAUD96(t, s)
	if len(warmRows) != 1 {
		t.Fatalf("warm finding rows = %d, want exactly one", len(warmRows))
	}
	if count, err := p.Snapshot(ctx); err != nil || count != 1 {
		t.Fatalf("snapshot canonical finding = count %d, err %v", count, err)
	}
	truncateReadModelAndCheckpoint(t, s)
	restored, err := p.RestoreFromSnapshot(ctx, log)
	if err != nil || !restored {
		t.Fatalf("restore canonical finding aliases = restored %t, err %v", restored, err)
	}
	if snapshotRows := discoveryRowsAUD96(t, s); !reflect.DeepEqual(snapshotRows, warmRows) {
		t.Fatalf("snapshot restore changed exact discovery rows:\n warm=%v\nrestored=%v", warmRows, snapshotRows)
	}
	for pass := 1; pass <= 2; pass++ {
		if err := p.Rebuild(ctx, log); err != nil {
			t.Fatalf("rebuild pass %d: %v", pass, err)
		}
		if rebuilt := discoveryRowsAUD96(t, s); !reflect.DeepEqual(rebuilt, warmRows) {
			t.Fatalf("rebuild pass %d changed exact discovery rows:\n warm=%v\nrebuilt=%v", pass, warmRows, rebuilt)
		}
	}
}

func TestDiscoveryFindingReplayRejectsConflictingSemanticPayloadWithoutMutationAUD96(t *testing.T) {
	s := newStore(t)
	log := openLog(t)
	ctx := context.Background()
	p := projections.New(s)

	appendAUD96DiscoveryBase(t, log)
	canonicalAt := time.Date(2026, 8, 10, 7, 3, 10, 0, time.UTC)
	mustAppendDiscoveryFindingAUD96(t, log, aud96EarlierFinding, canonicalAt, 82, `{"action":"investigate"}`)
	if err := p.ProjectCatchUp(ctx, log); err != nil {
		t.Fatalf("project canonical finding: %v", err)
	}
	before := discoveryRowsAUD96(t, s)
	checkpoint, err := s.ProjectionCheckpoint(ctx)
	if err != nil {
		t.Fatal(err)
	}

	mustAppendDiscoveryFindingAUD96(t, log, aud96ConflictingFind, canonicalAt.Add(time.Second), 99, `{"action":"silently-different"}`)
	err = p.ProjectCatchUp(ctx, log)
	if err == nil {
		t.Fatal("conflicting immutable discovery payload replay succeeded; want fail-closed conflict")
	}
	for _, want := range []string{
		"discovery finding identity conflict",
		tenantA,
		aud96EarlierFinding,
		aud96ConflictingFind,
		aud96RunID,
		"shadow-ingress.demo.trstctl.local:443",
		"risk_score",
		"metadata",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("conflict error %q does not contain actionable field %q", err, want)
		}
	}
	if after := discoveryRowsAUD96(t, s); !reflect.DeepEqual(after, before) {
		t.Fatalf("conflicting replay mutated the committed row:\n before=%v\n after=%v", before, after)
	}
	afterCheckpoint, err := s.ProjectionCheckpoint(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if afterCheckpoint != checkpoint {
		t.Fatalf("checkpoint advanced across conflict: before=%d after=%d", checkpoint, afterCheckpoint)
	}
}

func TestDiscoveryFindingReplayCanonicalizesDerivedSSHInventoryAUD101(t *testing.T) {
	s := newStore(t)
	log := openLog(t)
	ctx := context.Background()
	p := projections.New(s)

	appendAUD96DiscoveryBase(t, log)
	if err := p.ProjectCatchUp(ctx, log); err != nil {
		t.Fatalf("project discovery base: %v", err)
	}
	earlierAt := time.Date(2026, 8, 10, 7, 10, 0, 0, time.UTC)
	laterAt := earlierAt.Add(5 * time.Millisecond)
	mustAppendSSHDiscoveryFindingAUD101(t, log, aud101EarlierSSH, earlierAt)
	later := mustAppendSSHDiscoveryFindingAUD101(t, log, aud101LaterSSH, laterAt)
	if err := p.Apply(ctx, later); err != nil {
		t.Fatalf("project out-of-order SSH duplicate: %v", err)
	}
	if err := p.ProjectCatchUp(ctx, log); err != nil {
		t.Fatalf("catch up SSH duplicate: %v", err)
	}

	warm := sshRowsAUD101(t, s)
	if len(warm) != 1 {
		t.Fatalf("warm SSH rows = %d, want one: %v", len(warm), warm)
	}
	if !strings.Contains(warm[0], `"id": "`+aud101EarlierSSH+`"`) {
		t.Fatalf("warm SSH row did not canonicalize to earliest event id %s: %s", aud101EarlierSSH, warm[0])
	}
	for pass := 1; pass <= 2; pass++ {
		if err := p.Rebuild(ctx, log); err != nil {
			t.Fatalf("rebuild pass %d: %v", pass, err)
		}
		if rebuilt := sshRowsAUD101(t, s); !reflect.DeepEqual(rebuilt, warm) {
			t.Fatalf("rebuild pass %d changed derived SSH inventory:\n warm=%v\nrebuilt=%v", pass, warm, rebuilt)
		}
	}
}

func appendAUD96DiscoveryBase(t *testing.T, log *events.Log) {
	t.Helper()
	mustAppend(t, log, events.Event{Type: projections.EventTenantRegistered, TenantID: tenantA, Data: tenantRegistered("Acme")})
	mustAppend(t, log, events.Event{
		Type: projections.EventDiscoverySourceUpserted, TenantID: tenantA,
		Data: mustJSONAUD96(t, projections.DiscoverySourceUpserted{
			ID: aud96SourceID, Kind: "manual", Name: "manual-shadow-inventory", Config: json.RawMessage(`{}`),
		}),
	})
	mustAppend(t, log, events.Event{
		Type: projections.EventDiscoveryRunQueued, TenantID: tenantA,
		Data: mustJSONAUD96(t, projections.DiscoveryRunQueued{
			ID: aud96RunID, SourceID: aud96SourceID, RequestedBy: "demo-seeder",
		}),
	})
}

func mustAppendDiscoveryFindingAUD96(t *testing.T, log *events.Log, id string, at time.Time, riskScore int, metadata string) events.Event {
	t.Helper()
	event, err := log.Append(context.Background(), events.Event{
		Type: projections.EventDiscoveryFindingRecorded, TenantID: tenantA, Time: at,
		Data: mustJSONAUD96(t, projections.DiscoveryFindingRecorded{
			ID: id, RunID: aud96RunID, SourceID: aud96SourceID,
			Kind: "x509_certificate", Ref: "shadow-ingress.demo.trstctl.local:443",
			Provenance: "manual:shadow-inventory", Fingerprint: "demo-shadow-ingress-fingerprint",
			RiskScore: riskScore, Metadata: json.RawMessage(metadata),
		}),
	})
	if err != nil {
		t.Fatalf("append discovery finding %s: %v", id, err)
	}
	return event
}

func mustAppendSSHDiscoveryFindingAUD101(t *testing.T, log *events.Log, id string, at time.Time) events.Event {
	t.Helper()
	event, err := log.Append(context.Background(), events.Event{
		Type: projections.EventDiscoveryFindingRecorded, TenantID: tenantA, Time: at,
		Data: mustJSONAUD96(t, projections.DiscoveryFindingRecorded{
			ID: id, RunID: aud96RunID, SourceID: aud96SourceID,
			Kind: "ssh_key", Ref: "/home/demo/.ssh/authorized_keys",
			Provenance: "agent:authorized_keys", Fingerprint: "SHA256:aud101-stable-fingerprint",
			RiskScore: 71, Metadata: json.RawMessage(`{"source":"authorized_keys","location":"/home/demo/.ssh/authorized_keys","key_type":"ssh-ed25519","comment":"demo","standing_access":true,"orphaned":false}`),
		}),
	})
	if err != nil {
		t.Fatalf("append SSH discovery finding %s: %v", id, err)
	}
	return event
}

func mustJSONAUD96(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func discoveryRowsAUD96(t *testing.T, s *store.Store) []string {
	t.Helper()
	rows, err := s.SystemPool().Query(context.Background(),
		`SELECT to_jsonb(df.*)::text FROM discovery_findings df WHERE tenant_id = $1 ORDER BY id`, tenantA)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var row string
		if err := rows.Scan(&row); err != nil {
			t.Fatal(err)
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func sshRowsAUD101(t *testing.T, s *store.Store) []string {
	t.Helper()
	rows, err := s.SystemPool().Query(context.Background(),
		`SELECT to_jsonb(k.*)::text FROM ssh_keys k WHERE tenant_id = $1 AND fingerprint = 'SHA256:aud101-stable-fingerprint' ORDER BY id`, tenantA)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var row string
		if err := rows.Scan(&row); err != nil {
			t.Fatal(err)
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}
