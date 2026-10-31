// SPDX-License-Identifier: BUSL-1.1
package store_test

import (
	"bytes"
	"fmt"
	"github.com/jackc/pgx/v5"
	"testing"
	"trstctl.com/trstctl/internal/store"
)

// Candidate discovery is bounded routing metadata. It must never claim work,
// select another lane, or mistake delivered status for destruction authority.
func TestSettledEventKeyCleanupCandidatesAreBoundedExactAndReadOnly(t *testing.T) {
	s := newStore(t)
	type fixture struct {
		tenant, destination, lane, role, status string
		payload                                 []byte
		pending                                 []string
	}
	expected := map[int64]fixture{}
	var selectedIDs []int64
	put := func(row fixture, eligible bool) {
		t.Helper()
		var id int64
		if err := s.WithTenant(t.Context(), row.tenant, func(tx pgx.Tx) error {
			return tx.QueryRow(t.Context(), `INSERT INTO outbox(tenant_id,destination,effect_lane,payload,idempotency_key,required_agent_role,status,receiver_pending_ids)
    VALUES($1,$2,$3,$4,$5,$6,$7,$8::uuid[]) RETURNING id`, row.tenant, row.destination, row.lane, row.payload, fmt.Sprintf("cleanup-candidate-%d", len(expected)), row.role, row.status, row.pending).Scan(&id)
		}); err != nil {
			t.Fatal(err)
		}
		expected[id] = row
		if eligible {
			selectedIDs = append(selectedIDs, id)
		}
	}
	normal := func(tenant string) fixture {
		return fixture{tenant: tenant, destination: store.EventKeyDestructionDestination, lane: store.EventKeyDestructionDestination, role: "control_plane", status: "delivered", payload: []byte(`{}`), pending: []string{}}
	}
	for i := 0; i < 17; i++ {
		tenant := tenantA
		if i%2 != 0 {
			tenant = tenantB
		}
		row := normal(tenant)
		if i == 3 {
			row.lane = ""
		}
		put(row, true)
	}
	large := append([]byte(`{"padding":"`), bytes.Repeat([]byte("x"), 1<<20)...)
	large = append(large, []byte(`"}`)...)
	oversized := normal(tenantB)
	oversized.payload = large
	put(oversized, true)
	for _, kind := range []string{"pending", "processing", "other-destination", "other-lane", "agent-role", "unsettled"} {
		row := normal(tenantA)
		switch kind {
		case "pending", "processing":
			row.status = kind
		case "other-destination":
			row.destination += ".extra"
			row.lane = row.destination
		case "other-lane":
			row.lane = "other.effect"
		case "agent-role":
			row.role = "host"
		case "unsettled":
			row.pending = []string{"f248ad97-cc34-4e9c-b6bc-533e0ca09bb1"}
		}
		put(row, false)
	}
	first, err := s.ListSettledEventKeyDestructionIntents(t.Context(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 16 {
		t.Fatalf("first bounded page has %d candidates", len(first))
	}
	second, err := s.ListSettledEventKeyDestructionIntents(t.Context(), first[len(first)-1].ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(second) != 2 {
		t.Fatalf("continuation page has %d candidates", len(second))
	}
	all := append(first, second...)
	for i, row := range all {
		if row.ID != selectedIDs[i] || row.TenantID != expected[row.ID].tenant {
			t.Fatal("candidate scope or ordering changed")
		}
		want := expected[row.ID].payload
		if len(want) > 16385 {
			want = want[:16385]
		}
		if !bytes.Equal(row.Payload, want) {
			t.Fatal("bounded candidate changed original payload bytes")
		}
	}
	for id, row := range expected {
		var status string
		var attempts, size int
		if err := s.WithTenant(t.Context(), row.tenant, func(tx pgx.Tx) error {
			return tx.QueryRow(t.Context(), `SELECT status,attempts,octet_length(payload) FROM outbox WHERE tenant_id=$1 AND id=$2`, row.tenant, id).Scan(&status, &attempts, &size)
		}); err != nil {
			t.Fatal(err)
		}
		if status != row.status || attempts != 0 || size != len(row.payload) {
			t.Fatal("candidate discovery changed a durable row")
		}
	}
	var ready bool
	if err := s.SystemPool().QueryRow(t.Context(), `SELECT indisvalid AND indisready FROM pg_index WHERE indexrelid='outbox_event_key_cleanup_idx'::regclass`).Scan(&ready); err != nil || !ready {
		t.Fatalf("cleanup index not ready: %v", err)
	}
}
