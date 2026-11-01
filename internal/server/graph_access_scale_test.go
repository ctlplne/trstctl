// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"testing"
	"time"

	"trstctl.com/trstctl/internal/graph"
	"trstctl.com/trstctl/internal/store"
)

// G1: build time of the access graph on a large tenant, measured. The read
// models are seeded in bulk (as a projection would leave them) so the test
// times the graph build, not seeding: 2,000 people with roles, 5,000 API
// tokens, and 3,000 live PAM sessions over 50 databases, each requested by a
// person, attested to one of 100 workloads and approved by two people.
func TestAccessGraphBuildTimeOnALargeTenantG1(t *testing.T) {
	if testing.Short() {
		t.Skip("seeds a large tenant in PostgreSQL; skipped in -short")
	}
	st := newServerTestStore(t)
	ctx := t.Context()
	if err := st.UpsertTenant(ctx, store.Tenant{TenantID: servedTestTenant, Name: "G1 scale tenant"}); err != nil {
		t.Fatal(err)
	}
	const (
		people   = 2000
		tokens   = 5000
		sessions = 3000
		targets  = 50
	)
	for _, seed := range []string{
		`INSERT INTO tenant_members (tenant_id, subject, display_name, roles, source, status, created_at, updated_at)
		 SELECT $1, 'person-' || i, 'Person ' || i, ARRAY[CASE WHEN i % 10 = 0 THEN 'admin' ELSE 'operator' END], 'test', 'active', now(), now()
		   FROM generate_series(1, 2000) AS i`,
		`INSERT INTO api_tokens (id, tenant_id, token_hash, subject, scopes, created_at)
		 SELECT gen_random_uuid(), $1, 'g1-scale-' || i, 'person-' || (1 + i % 2000), ARRAY['graph:read'], now()
		   FROM generate_series(1, 5000) AS i`,
		`INSERT INTO operation_approval_requests (tenant_id, id, intent_digest, resource_kind, resource_id, action,
		        requester, required_approvals, status, created_at, expires_at, updated_at, consumed_at, consumed_event_id)
		 SELECT $1, md5('g1-approval-' || i)::uuid, 'digest-' || i, 'pam', 'pam:' || md5('g1-request-' || i)::uuid, 'activate',
		        'person-' || (1 + i % 2000), 2, 'consumed', now(), now() + interval '1 hour', now(), now(), md5('g1-event-' || i)::uuid
		   FROM generate_series(1, 3000) AS i`,
		`INSERT INTO operation_approval_decisions (tenant_id, request_id, intent_digest, approver, decision, event_id, decided_at)
		 SELECT $1, md5('g1-approval-' || i)::uuid, 'digest-' || i, 'person-' || (1 + (i + r) % 2000), 'approve',
		        md5('g1-decision-' || i || '-' || r)::uuid, now()
		   FROM generate_series(1, 3000) AS i, generate_series(1, 2) AS r`,
		`INSERT INTO pam_sessions (tenant_id, id, target_type, target_id, role, status, subject, requested_by,
		        started_at, expires_at, approval_request_id)
		 SELECT $1, md5('g1-session-' || i)::uuid, 'postgres', 'db-' || (i % 50), 'readonly', 'active',
		        'workload-' || (i % 100), 'person-' || (1 + i % 2000), now(), now() + interval '1 hour', md5('g1-approval-' || i)::uuid::text
		   FROM generate_series(1, 3000) AS i`,
	} {
		if _, err := st.SystemPool().Exec(ctx, seed, servedTestTenant); err != nil {
			t.Fatalf("seed the large tenant: %v", err)
		}
	}

	start := time.Now()
	g, err := graph.Build(ctx, st, servedTestTenant)
	build := time.Since(start)
	if err != nil {
		t.Fatal(err)
	}
	start = time.Now()
	answer := g.WhoCanReach("res:pam:postgres:db-7")
	reach := time.Since(start)
	start = time.Now()
	_, pathFound := g.PathBetween("person:person-8", "res:pam:postgres:db-7")
	path := time.Since(start)
	t.Logf("G1 large tenant: %d nodes, %d edges; build %s, who-can-reach %s, path %s",
		g.Order(), g.Size(), build.Round(time.Millisecond), reach.Round(time.Microsecond), path.Round(time.Microsecond))

	// people + roles + tokens + sessions + workloads + databases + the trstctl API
	if want := people + 2 + tokens + sessions + 100 + targets + 1; g.Order() != want {
		t.Fatalf("graph order = %d, want %d", g.Order(), want)
	}
	if len(answer.Access) != sessions/targets {
		t.Fatalf("who can reach db-7: %d sessions, want %d", len(answer.Access), sessions/targets)
	}
	for _, grant := range answer.Access {
		if len(grant.Holders) != 2 || len(grant.Approvers) != 2 {
			t.Fatalf("session %s: %d holders, %d approvers", grant.Credential.ID, len(grant.Holders), len(grant.Approvers))
		}
	}
	if !pathFound {
		t.Fatal("person-8 requested a session to db-7 (session 7), but no path was found")
	}
	// A generous bound that only catches a pathological regression; the logged
	// numbers are the measurement.
	if build > 60*time.Second {
		t.Fatalf("building a %d-node access graph took %s", g.Order(), build)
	}
}
