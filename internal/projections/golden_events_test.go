// SPDX-License-Identifier: BUSL-1.1

package projections_test

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
)

const goldenEventsPath = "testdata/golden-events-v1.jsonl"

// TestGoldenEventBytesReplayIntoReadModel is the OPS-EVENT-GOLDEN-001
// acceptance. The fixture holds FROZEN serialized v1 event envelopes —
// captured output, not structs re-marshaled by this test — so a payload field
// rename or envelope change that would strand an existing installation's
// event log fails HERE, not at a customer upgrade. The projector must decode
// every frozen byte stream and project the expected read-model rows.
//
// Regenerate deliberately (a schema-compat decision, reviewed like one):
//
//	TRSTCTL_UPDATE_GOLDEN=1 go test ./internal/projections -run GoldenEvent -count=1
func TestGoldenEventBytesReplayIntoReadModel(t *testing.T) {
	if os.Getenv("TRSTCTL_UPDATE_GOLDEN") == "1" {
		writeGoldenEvents(t)
	}
	raw, err := os.Open(filepath.FromSlash(goldenEventsPath))
	if err != nil {
		t.Fatalf("frozen golden events missing (%v); regenerate with TRSTCTL_UPDATE_GOLDEN=1 only as a reviewed schema decision", err)
	}
	defer func() { _ = raw.Close() }()

	s := newStore(t)
	ctx := context.Background()
	proj := projections.New(s)

	scanner := bufio.NewScanner(raw)
	scanner.Buffer(make([]byte, 1<<20), 1<<20)
	lines := 0
	for scanner.Scan() {
		if len(scanner.Bytes()) == 0 {
			continue
		}
		lines++
		var e events.Event
		if err := json.Unmarshal(scanner.Bytes(), &e); err != nil {
			t.Fatalf("frozen event line %d does not decode as an event envelope: %v", lines, err)
		}
		if err := proj.Apply(ctx, e); err != nil {
			t.Fatalf("current projector cannot replay frozen v1 event %q (line %d): %v", e.Type, lines, err)
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if lines < 4 {
		t.Fatalf("golden fixture has %d events; the frozen corpus should cover tenant, owner, and ceremony flows", lines)
	}

	// The frozen bytes must land as real rows, not merely "no error".
	tenant, err := s.GetTenant(ctx, goldenTenantID)
	if err != nil || tenant.Name != "Golden Fixture Tenant" {
		t.Fatalf("frozen tenant.registered did not project: %+v err=%v", tenant, err)
	}
	owner, err := s.GetOwner(ctx, goldenTenantID, "00000000-0000-4000-8000-00000000f001")
	if err != nil || owner.Name != "golden-owner" {
		t.Fatalf("frozen owner.created did not project: %+v err=%v", owner, err)
	}
	ceremony, err := s.GetKeyCeremony(ctx, goldenTenantID, "00000000-0000-4000-8000-00000000f002")
	if err != nil || ceremony.Status != "pending" || ceremony.Approvals != 1 {
		t.Fatalf("frozen ceremony events did not project (want pending with 1 approval): %+v err=%v", ceremony, err)
	}
}

const goldenTenantID = "00000000-0000-4000-8000-00000000f000"

// writeGoldenEvents captures the CURRENT wire form once; after commit the
// bytes are immutable evidence of what a released binary wrote.
func writeGoldenEvents(t *testing.T) {
	t.Helper()
	base := time.Date(2026, 7, 12, 0, 0, 0, 0, time.UTC)
	marshal := func(v any) json.RawMessage {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	fixture := []events.Event{
		{ID: "00000000-0000-4000-8000-00000000e001", Sequence: 1, Type: projections.EventTenantRegistered, TenantID: goldenTenantID, Time: base,
			Data: marshal(map[string]string{"name": "Golden Fixture Tenant"})},
		{ID: "00000000-0000-4000-8000-00000000e002", Sequence: 2, Type: projections.EventOwnerCreated, TenantID: goldenTenantID, Time: base.Add(time.Second),
			Data: marshal(projections.OwnerCreated{ID: "00000000-0000-4000-8000-00000000f001", Kind: "workload", Name: "golden-owner", Email: "golden-owner@example.com"})},
		{ID: "00000000-0000-4000-8000-00000000e003", Sequence: 3, Type: projections.EventCACeremonyStarted, TenantID: goldenTenantID, Time: base.Add(2 * time.Second),
			Data: marshal(projections.CACeremonyStarted{CeremonyID: "00000000-0000-4000-8000-00000000f002", Purpose: "root:golden", Threshold: 2, Opener: "operator"})},
		{ID: "00000000-0000-4000-8000-00000000e004", Sequence: 4, Type: projections.EventCACeremonyApproved, TenantID: goldenTenantID, Time: base.Add(3 * time.Second),
			Data: marshal(projections.CACeremonyApproved{CeremonyID: "00000000-0000-4000-8000-00000000f002", Custodian: "custodian-one"})},
	}
	if err := os.MkdirAll(filepath.Dir(filepath.FromSlash(goldenEventsPath)), 0o755); err != nil { // #nosec G301 -- fixture tree in a test tempdir; the mode is part of the fixture (CWE-276)
		t.Fatal(err)
	}
	f, err := os.Create(filepath.FromSlash(goldenEventsPath))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	for _, e := range fixture {
		line, err := json.Marshal(e)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fmt.Fprintf(f, "%s\n", line); err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("regenerated %s with %d events — commit only as a reviewed schema decision", goldenEventsPath, len(fixture))
}
