// SPDX-License-Identifier: MPL-2.0

package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/store"
)

// The agent job ledger's claim semantics (epic A1).
//
// Work that touches a customer's estate is decided in the control plane and
// executed in the customer's environment, which means the control plane hands
// work out rather than doing it. Everything that can go wrong with handing work
// out is here: two agents reaching for the same job, an agent dying holding one,
// an agent reporting twice, an agent trying to touch a job it does not hold.
//
// A claim is a lease, not an assignment. That single choice is what makes a dead
// agent recoverable without anybody noticing it died.

const (
	jobDeploy = "connector.deploy"
	jobVerify = "endpoint.verify"
)

func seedJobs(t *testing.T, ctx context.Context, st *store.Store, tenantID string, n int, destination string) {
	t.Helper()
	for i := 0; i < n; i++ {
		if err := st.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx,
				`INSERT INTO outbox (tenant_id, destination, payload, idempotency_key)
				 VALUES ($1, $2, $3, $4)`,
				tenantID, destination, []byte(`{"job":true}`), destination+":"+time.Now().Format("150405.000000000")+"-"+itoa(i))
			return err
		}); err != nil {
			t.Fatalf("seed job: %v", err)
		}
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}

func TestAgentJobClaimIsALeaseNotAnAssignment(t *testing.T) {
	if testing.Short() {
		t.Skip("starts an embedded PostgreSQL; skipped in -short")
	}
	ctx := context.Background()
	st, tenantID := newStore(t), tenantA
	seedAgentJobTenant(t, ctx, st, tenantID)
	const agentA = "11111111-1111-1111-1111-111111111111"
	const agentB = "22222222-2222-2222-2222-222222222222"

	seedJobs(t, ctx, st, tenantID, 3, jobDeploy)
	now := time.Now().UTC()

	claimed, err := st.ClaimAgentJobs(ctx, tenantID, agentA, []string{jobDeploy}, nil, 2, time.Minute, now)
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	if len(claimed) != 2 {
		t.Fatalf("claimed %d jobs, want 2", len(claimed))
	}
	for _, job := range claimed {
		if job.ClaimAttempts != 1 || job.Destination != jobDeploy || len(job.Payload) == 0 {
			t.Fatalf("claimed job is not fully populated: %+v", job)
		}
	}

	// A second agent polling at the same moment takes different work — the whole
	// point of SKIP LOCKED. A fleet must fan out across the queue, not serialize
	// on its head or duplicate each other's jobs.
	other, err := st.ClaimAgentJobs(ctx, tenantID, agentB, []string{jobDeploy}, nil, 5, time.Minute, now)
	if err != nil {
		t.Fatalf("second claim: %v", err)
	}
	if len(other) != 1 {
		t.Fatalf("second agent claimed %d jobs, want the 1 remaining", len(other))
	}
	for _, a := range claimed {
		for _, b := range other {
			if a.ID == b.ID {
				t.Fatalf("job %d was claimed by two agents at once", a.ID)
			}
		}
	}

	// Nothing is left, and a third poll is empty rather than an error.
	empty, err := st.ClaimAgentJobs(ctx, tenantID, agentA, []string{jobDeploy}, nil, 5, time.Minute, now)
	if err != nil || len(empty) != 0 {
		t.Fatalf("third claim = %d jobs (err %v), want 0", len(empty), err)
	}
}

func TestAgentJobLeaseExpiryReturnsWorkFromADeadAgent(t *testing.T) {
	if testing.Short() {
		t.Skip("starts an embedded PostgreSQL; skipped in -short")
	}
	ctx := context.Background()
	st, tenantID := newStore(t), tenantA
	seedAgentJobTenant(t, ctx, st, tenantID)
	const dead = "33333333-3333-3333-3333-333333333333"
	const alive = "44444444-4444-4444-4444-444444444444"

	seedJobs(t, ctx, st, tenantID, 1, jobVerify)
	start := time.Now().UTC()

	claimed, err := st.ClaimAgentJobs(ctx, tenantID, dead, []string{jobVerify}, nil, 1, 30*time.Second, start)
	if err != nil || len(claimed) != 1 {
		t.Fatalf("initial claim = %d (err %v)", len(claimed), err)
	}

	// While the lease holds, nobody else can take it. This is what stops two
	// agents deploying to the same target at once.
	if got, err := st.ClaimAgentJobs(ctx, tenantID, alive, []string{jobVerify}, nil, 1, 30*time.Second, start.Add(time.Second)); err != nil || len(got) != 0 {
		t.Fatalf("a held lease was claimable by another agent: %d (err %v)", len(got), err)
	}

	// The agent dies. It stops extending, the lease lapses, and the work comes
	// back — without anyone noticing the machine is gone.
	after := start.Add(time.Minute)
	freed, err := st.ReclaimExpiredAgentJobs(ctx, after)
	if err != nil {
		t.Fatalf("reclaim: %v", err)
	}
	if freed != 1 {
		t.Fatalf("reclaimed %d lapsed leases, want 1", freed)
	}
	recovered, err := st.ClaimAgentJobs(ctx, tenantID, alive, []string{jobVerify}, nil, 1, 30*time.Second, after)
	if err != nil || len(recovered) != 1 {
		t.Fatalf("a dead agent's work did not return to the queue: %d (err %v)", len(recovered), err)
	}
	if recovered[0].ClaimAttempts != 2 {
		t.Errorf("claim attempts = %d, want 2 — a job taken twice must say so, or a cycling job is invisible",
			recovered[0].ClaimAttempts)
	}
}

func TestAgentJobExtendCompleteAndReleaseOnlyWorkForTheHolder(t *testing.T) {
	if testing.Short() {
		t.Skip("starts an embedded PostgreSQL; skipped in -short")
	}
	ctx := context.Background()
	st, tenantID := newStore(t), tenantA
	seedAgentJobTenant(t, ctx, st, tenantID)
	const holder = "55555555-5555-5555-5555-555555555555"
	const impostor = "66666666-6666-6666-6666-666666666666"

	seedJobs(t, ctx, st, tenantID, 2, jobDeploy)
	now := time.Now().UTC()
	claimed, err := st.ClaimAgentJobs(ctx, tenantID, holder, []string{jobDeploy}, nil, 2, time.Minute, now)
	if err != nil || len(claimed) != 2 {
		t.Fatalf("claim = %d (err %v)", len(claimed), err)
	}
	first, second := claimed[0], claimed[1]

	// Only the holder may extend. Otherwise "the lease is alive" stops meaning
	// "the agent doing the work is alive", which is the only thing it is for.
	if ok, err := st.ExtendAgentJobClaim(ctx, tenantID, impostor, first.ID, now.Add(time.Hour)); err != nil || ok {
		t.Fatalf("an agent extended a lease it does not hold: ok=%v err=%v", ok, err)
	}
	if ok, err := st.ExtendAgentJobClaim(ctx, tenantID, holder, first.ID, now.Add(time.Hour)); err != nil || !ok {
		t.Fatalf("the holder could not extend its own lease: ok=%v err=%v", ok, err)
	}

	// Same for closing the claim: a report from a non-holder changes nothing.
	if _, _, ok, err := st.MarkAgentJobCompleted(ctx, tenantID, impostor, first.ID, now); err != nil || ok {
		t.Fatalf("an agent closed a claim it does not hold: ok=%v err=%v", ok, err)
	}
	dest, idem, ok, err := st.MarkAgentJobCompleted(ctx, tenantID, holder, first.ID, now)
	if err != nil || !ok {
		t.Fatalf("the holder could not close its own claim: ok=%v err=%v", ok, err)
	}
	// The caller needs both to finish the delivery through the orchestrator,
	// which is where the dispatch lease and circuit accounting live.
	if dest != jobDeploy || idem == "" {
		t.Fatalf("closing a claim did not return the delivery key: %q/%q", dest, idem)
	}
	// A replayed report is a no-op rather than a second delivery — which is what
	// makes an at-least-once report safe to send twice.
	if _, _, ok, err := st.MarkAgentJobCompleted(ctx, tenantID, holder, first.ID, now); err != nil || ok {
		t.Fatalf("a replayed completion was applied again: ok=%v err=%v", ok, err)
	}

	// Releasing hands the work back immediately: a failure on one host is not
	// evidence the work is impossible.
	if ok, err := st.ReleaseAgentJob(ctx, tenantID, holder, second.ID, "nginx -t failed: /etc/nginx/tls.key is unreadable"); err != nil || !ok {
		t.Fatalf("release: ok=%v err=%v", ok, err)
	}
	// The agent's own words must not land in the durable row: an agent executes
	// against systems that echo credentials back in error strings, and an
	// unbounded string on the queue is exactly where that becomes permanent.
	var persisted string
	if err := st.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT coalesce(last_error, '') FROM outbox WHERE tenant_id = $1 AND id = $2`,
			tenantID, second.ID).Scan(&persisted)
	}); err != nil {
		t.Fatalf("read persisted failure reason: %v", err)
	}
	if persisted != store.AgentFailureReported {
		t.Fatalf("persisted failure reason = %q, want the closed-set marker %q", persisted, store.AgentFailureReported)
	}
	requeued, err := st.ClaimAgentJobs(ctx, tenantID, impostor, []string{jobDeploy}, nil, 5, time.Minute, now)
	if err != nil || len(requeued) != 1 || requeued[0].ID != second.ID {
		t.Fatalf("a released job did not become claimable again: %+v (err %v)", requeued, err)
	}
	if requeued[0].Attempts == 0 {
		t.Error("a failed attempt did not count; a job failing forever must be visible")
	}
}

// TestAgentJobQueueDepthsCarryNoTenantData pins the observability contract: an
// operator needs to know the fabric is moving without being handed anyone's data
// to know it — the same rule the bulkhead surface already follows.
func TestAgentJobQueueDepthsCarryNoTenantData(t *testing.T) {
	if testing.Short() {
		t.Skip("starts an embedded PostgreSQL; skipped in -short")
	}
	ctx := context.Background()
	st, tenantID := newStore(t), tenantA
	seedAgentJobTenant(t, ctx, st, tenantID)
	const agent = "77777777-7777-7777-7777-777777777777"

	seedJobs(t, ctx, st, tenantID, 3, jobDeploy)
	seedJobs(t, ctx, st, tenantID, 1, jobVerify)
	now := time.Now().UTC()
	if _, err := st.ClaimAgentJobs(ctx, tenantID, agent, []string{jobDeploy}, nil, 1, time.Minute, now); err != nil {
		t.Fatalf("claim: %v", err)
	}

	depths, err := st.AgentJobQueueDepths(ctx, []string{jobDeploy, jobVerify})
	if err != nil {
		t.Fatalf("queue depths: %v", err)
	}
	byDest := map[string]store.AgentJobQueueDepth{}
	for _, d := range depths {
		byDest[d.Destination] = d
	}
	if got := byDest[jobDeploy]; got.Pending != 2 || got.Claimed != 1 {
		t.Errorf("%s depth = pending %d claimed %d, want 2/1", jobDeploy, got.Pending, got.Claimed)
	}
	if got := byDest[jobVerify]; got.Pending != 1 || got.Claimed != 0 {
		t.Errorf("%s depth = pending %d claimed %d, want 1/0", jobVerify, got.Pending, got.Claimed)
	}
	if byDest[jobDeploy].OldestUnclaimedAt == nil {
		t.Error("oldest-unclaimed age is missing; a stalled queue is invisible without it")
	}
}

func seedAgentJobTenant(t *testing.T, ctx context.Context, st *store.Store, tenantID string) {
	t.Helper()
	if err := st.UpsertTenant(ctx, store.Tenant{TenantID: tenantID, Name: "agent-jobs"}); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
}

// TestClaimHonorsPerRowRoleDemand is A3's row-level gate at the store: the same
// kind, four different demands, and each agent receives exactly the rows its
// certificate's roles satisfy. The 'control_plane' stamp matches no role, so a
// cloud-store deploy is handed to nobody; the empty demand preserves pre-A3
// behaviour for every row enqueued before the census existed.
func TestClaimHonorsPerRowRoleDemand(t *testing.T) {
	st, tenantID := newStore(t), tenantA
	ctx := context.Background()
	now := time.Now().UTC()

	seed := func(idem, role string) {
		t.Helper()
		if err := st.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx,
				`INSERT INTO outbox (tenant_id, destination, payload, idempotency_key, required_agent_role)
				 VALUES ($1, $2, $3, $4, $5)`,
				tenantID, jobDeploy, []byte(`{}`), idem, role)
			return err
		}); err != nil {
			t.Fatalf("seed %s: %v", idem, err)
		}
	}
	seed("legacy", "")
	seed("nginx-deploy", "host")
	seed("f5-deploy", "network")
	seed("acm-deploy", "control_plane")

	hostAgent := "aaaaaaaa-0000-0000-0000-000000000001"
	relay := "aaaaaaaa-0000-0000-0000-000000000002"

	hostGot, err := st.ClaimAgentJobs(ctx, tenantID, hostAgent, []string{jobDeploy}, []string{"host"}, 10, time.Minute, now)
	if err != nil {
		t.Fatalf("host claim: %v", err)
	}
	hostKeys := map[string]bool{}
	for _, j := range hostGot {
		hostKeys[j.IdempotencyKey] = true
	}
	if len(hostGot) != 2 || !hostKeys["legacy"] || !hostKeys["nginx-deploy"] {
		t.Fatalf("host agent claimed %v, want exactly [legacy nginx-deploy]", hostKeys)
	}

	relayGot, err := st.ClaimAgentJobs(ctx, tenantID, relay, []string{jobDeploy}, []string{"network"}, 10, time.Minute, now)
	if err != nil {
		t.Fatalf("relay claim: %v", err)
	}
	if len(relayGot) != 1 || relayGot[0].IdempotencyKey != "f5-deploy" {
		t.Fatalf("relay claimed %v, want exactly [f5-deploy]", relayGot)
	}

	// The cloud-store row is left for the control plane no matter who asks.
	nobody, err := st.ClaimAgentJobs(ctx, tenantID, relay, []string{jobDeploy}, []string{"host", "network"}, 10, time.Minute, now.Add(2*time.Minute))
	if err != nil {
		t.Fatalf("dual-role claim: %v", err)
	}
	for _, j := range nobody {
		if j.IdempotencyKey == "acm-deploy" {
			t.Fatal("a control_plane-stamped row was handed to an agent")
		}
	}
}
