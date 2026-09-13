// SPDX-License-Identifier: MPL-2.0

package store_test

import (
	"context"
	"fmt"
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

func TestAgentJobExtendAndReleaseOnlyWorkForTheHolder(t *testing.T) {
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
	if _, found, err := st.AgentJobClaimForResult(ctx, tenantID, holder, first.ID, first.ClaimAttempts+1, now); err != nil || found {
		t.Fatalf("a stale/future claim generation authorized result projection: found=%v err=%v", found, err)
	}
	if binding, found, err := st.AgentJobClaimForResult(ctx, tenantID, holder, first.ID, first.ClaimAttempts, now); err != nil || !found || binding.Destination != jobDeploy {
		t.Fatalf("current result claim binding=%+v found=%v err=%v", binding, found, err)
	}
	// Only the holder may extend. Otherwise "the lease is alive" stops meaning
	// "the agent doing the work is alive", which is the only thing it is for.
	if ok, err := st.ExtendAgentJobClaim(ctx, tenantID, holder, first.ID, first.ClaimAttempts+1, now, now.Add(time.Hour)); err != nil || ok {
		t.Fatalf("wrong attempt extended its lease: ok=%v err=%v", ok, err)
	}
	if ok, err := st.ExtendAgentJobClaim(ctx, tenantID, holder, first.ID, first.ClaimAttempts, now.Add(2*time.Minute), now.Add(time.Hour)); err != nil || ok {
		t.Fatalf("expired attempt resurrected its lease: ok=%v err=%v", ok, err)
	}
	if ok, err := st.ExtendAgentJobClaim(ctx, tenantID, impostor, first.ID, first.ClaimAttempts, now, now.Add(time.Hour)); err != nil || ok {
		t.Fatalf("an agent extended a lease it does not hold: ok=%v err=%v", ok, err)
	}
	if ok, err := st.ExtendAgentJobClaim(ctx, tenantID, holder, first.ID, first.ClaimAttempts, now, now.Add(time.Hour)); err != nil || !ok {
		t.Fatalf("the holder could not extend its own lease: ok=%v err=%v", ok, err)
	}

	// A late report cannot release a newer claim, including one held by the same
	// agent. An expired claim also cannot mutate retry scheduling.
	if ok, err := st.ReleaseAgentJob(ctx, tenantID, holder, second.ID, second.ClaimAttempts+1, "failed", now); err != nil || ok {
		t.Fatalf("wrong generation released a claim: ok=%v err=%v", ok, err)
	}
	if ok, err := st.ReleaseAgentJob(ctx, tenantID, holder, second.ID, second.ClaimAttempts, "failed", now.Add(2*time.Minute)); err != nil || ok {
		t.Fatalf("expired generation released a claim: ok=%v err=%v", ok, err)
	}
	if ok, err := st.ReleaseAgentJob(ctx, tenantID, holder, second.ID, second.ClaimAttempts, "nginx -t failed: /etc/nginx/tls.key is unreadable", now); err != nil || !ok {
		t.Fatalf("release: ok=%v err=%v", ok, err)
	}
	// The agent's own words must not land in the durable row: an agent executes
	// against systems that echo credentials back in error strings, and an
	// unbounded string on the queue is exactly where that becomes permanent.
	var persisted string
	var retryAt time.Time
	if err := st.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT coalesce(last_error, ''), agent_next_attempt_at FROM outbox WHERE tenant_id = $1 AND id = $2`,
			tenantID, second.ID).Scan(&persisted, &retryAt)
	}); err != nil {
		t.Fatalf("read persisted failure reason: %v", err)
	}
	if persisted != store.AgentFailureReported {
		t.Fatalf("persisted failure reason = %q, want the closed-set marker %q", persisted, store.AgentFailureReported)
	}
	if delay := retryAt.Sub(now); delay < 2500*time.Millisecond || delay > 5*time.Second {
		t.Fatalf("first retry delay = %s, want 2.5–5 seconds", delay)
	}
	if early, err := st.ClaimAgentJobs(ctx, tenantID, impostor, []string{jobDeploy}, nil, 5, time.Minute, now); err != nil || len(early) != 0 {
		t.Fatalf("failed work immediately reclaimable: jobs=%d err=%v", len(early), err)
	}
	requeued, err := st.ClaimAgentJobs(ctx, tenantID, impostor, []string{jobDeploy}, nil, 5, time.Minute, retryAt.Add(time.Millisecond))
	if err != nil || len(requeued) != 1 || requeued[0].ID != second.ID {
		t.Fatalf("a released job did not become claimable again: %+v (err %v)", requeued, err)
	}
	if requeued[0].Attempts == 0 {
		t.Error("a failed attempt did not count; a job failing forever must be visible")
	}
}

func TestCompletedPendingAgentJobIsNeverReclaimed(t *testing.T) {
	if testing.Short() {
		t.Skip("starts an embedded PostgreSQL; skipped in -short")
	}
	ctx := context.Background()
	st, tenantID := newStore(t), tenantA
	seedAgentJobTenant(t, ctx, st, tenantID)
	const agentID = "77777777-7777-7777-7777-777777777777"
	seedJobs(t, ctx, st, tenantID, 1, jobDeploy)
	now := time.Now().UTC()
	claimed, err := st.ClaimAgentJobs(ctx, tenantID, agentID, []string{jobDeploy}, nil, 1, time.Minute, now)
	if err != nil || len(claimed) != 1 {
		t.Fatalf("claim jobs=%+v err=%v", claimed, err)
	}
	if err := st.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`UPDATE outbox SET claim_completed_at = $3 WHERE tenant_id = $1 AND id = $2`,
			tenantID, claimed[0].ID, now)
		return err
	}); err != nil {
		t.Fatalf("seed pre-AUD-94 split row: %v", err)
	}

	reclaimed, err := st.ClaimAgentJobs(ctx, tenantID, agentID, []string{jobDeploy}, nil, 1, time.Minute, now.Add(2*time.Minute))
	if err != nil || len(reclaimed) != 0 {
		t.Fatalf("a completed pending row was reclaimed: jobs=%+v err=%v", reclaimed, err)
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
				`INSERT INTO outbox (tenant_id, destination, payload, idempotency_key, required_agent_role, required_agent_id)
				 VALUES ($1, $2, $3, $4, $5, CASE WHEN $5 = 'host' THEN 'aaaaaaaa-0000-0000-0000-000000000001'::uuid END)`,
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

// TestRedeemAgentJobCredentialIsSingleUsePerAttempt is A3 acceptance #2 at the
// store: one redemption per (job, agent, attempt), bound to the live lease.
// Every refusal path returns the same ok=false; the classifier then names the
// cause for the audit event only.
func TestRedeemAgentJobCredentialIsSingleUsePerAttempt(t *testing.T) {
	st, tenantID := newStore(t), tenantA
	ctx := context.Background()
	now := time.Now().UTC()
	holder := "bbbbbbbb-0000-0000-0000-000000000001"
	impostor := "bbbbbbbb-0000-0000-0000-000000000002"

	if err := st.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO outbox (tenant_id, destination, payload, idempotency_key, required_agent_role)
			 VALUES ($1, $2, $3, $4, 'network')`,
			tenantID, jobDeploy, []byte(`{}`), "redeem:f5-1")
		return err
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	claimed, err := st.ClaimAgentJobs(ctx, tenantID, holder, []string{jobDeploy}, []string{"network"}, 1, time.Minute, now)
	if err != nil || len(claimed) != 1 {
		t.Fatalf("claim: %v (%d)", err, len(claimed))
	}
	job := claimed[0]
	binding := []byte("test-binding-digest")

	// First redemption by the lease holder at the current attempt: granted.
	first, ok, err := st.RedeemAgentJobCredential(ctx, tenantID, holder, job.ID, job.ClaimAttempts, binding, now)
	if err != nil || !ok {
		t.Fatalf("first redemption refused: ok=%v err=%v", ok, err)
	}
	if first.AuditRef == "" {
		t.Fatal("granted redemption carries no audit ref")
	}
	if !first.ExpiresAt.Equal(job.ClaimExpiresAt.UTC()) {
		t.Fatalf("redemption expiry %v is not bound to the claim lease %v", first.ExpiresAt, job.ClaimExpiresAt)
	}

	// Replay by the same holder: refused, and classified as replayed.
	if _, ok, err := st.RedeemAgentJobCredential(ctx, tenantID, holder, job.ID, job.ClaimAttempts, binding, now); err != nil || ok {
		t.Fatalf("replayed redemption was granted: ok=%v err=%v", ok, err)
	}
	if reason, err := st.AgentJobRedemptionRefusalReason(ctx, tenantID, holder, job.ID, job.ClaimAttempts, now); err != nil || reason != store.AgentRedemptionRefusedReplayed {
		t.Fatalf("replay classified %q (%v), want %q", reason, err, store.AgentRedemptionRefusedReplayed)
	}

	// A second agent that does not hold the lease: refused, lease-not-held.
	if _, ok, err := st.RedeemAgentJobCredential(ctx, tenantID, impostor, job.ID, job.ClaimAttempts, binding, now); err != nil || ok {
		t.Fatalf("impostor redemption was granted: ok=%v err=%v", ok, err)
	}

	// A stale attempt from the holder: refused, attempt-stale.
	if _, ok, err := st.RedeemAgentJobCredential(ctx, tenantID, holder, job.ID, job.ClaimAttempts+7, binding, now); err != nil || ok {
		t.Fatalf("stale-attempt redemption was granted: ok=%v err=%v", ok, err)
	}
	if reason, err := st.AgentJobRedemptionRefusalReason(ctx, tenantID, holder, job.ID, job.ClaimAttempts+7, now); err != nil || reason != store.AgentRedemptionRefusedAttemptStale {
		t.Fatalf("stale attempt classified %q (%v), want %q", reason, err, store.AgentRedemptionRefusedAttemptStale)
	}
}

// TestRedemptionAfterLeaseLapseGoesToTheNewHolder: the lease lapses, another
// agent claims the SAME job — a new attempt — and redemption follows the lease:
// the new holder redeems its attempt, the old holder is refused everywhere.
func TestRedemptionAfterLeaseLapseGoesToTheNewHolder(t *testing.T) {
	st, tenantID := newStore(t), tenantA
	ctx := context.Background()
	start := time.Now().UTC()
	dead := "cccccccc-0000-0000-0000-000000000001"
	alive := "cccccccc-0000-0000-0000-000000000002"

	if err := st.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO outbox (tenant_id, destination, payload, idempotency_key, required_agent_role)
			 VALUES ($1, $2, $3, $4, 'network')`,
			tenantID, jobDeploy, []byte(`{}`), "redeem:lapse-1")
		return err
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	firstClaim, err := st.ClaimAgentJobs(ctx, tenantID, dead, []string{jobDeploy}, []string{"network"}, 1, 10*time.Second, start)
	if err != nil || len(firstClaim) != 1 {
		t.Fatalf("first claim: %v (%d)", err, len(firstClaim))
	}
	// The dead agent never redeems; its lease lapses; a live agent claims.
	after := start.Add(time.Minute)
	secondClaim, err := st.ClaimAgentJobs(ctx, tenantID, alive, []string{jobDeploy}, []string{"network"}, 1, time.Minute, after)
	if err != nil || len(secondClaim) != 1 {
		t.Fatalf("reclaim after lapse: %v (%d)", err, len(secondClaim))
	}
	fresh := secondClaim[0]
	if fresh.ClaimAttempts != firstClaim[0].ClaimAttempts+1 {
		t.Fatalf("reclaim attempt = %d, want %d", fresh.ClaimAttempts, firstClaim[0].ClaimAttempts+1)
	}

	// The dead agent's redemption at its old attempt: refused.
	if _, ok, err := st.RedeemAgentJobCredential(ctx, tenantID, dead, fresh.ID, firstClaim[0].ClaimAttempts, []byte("b"), after); err != nil || ok {
		t.Fatalf("dead agent redeemed after losing the lease: ok=%v err=%v", ok, err)
	}
	// The live holder's redemption at the fresh attempt: granted.
	if _, ok, err := st.RedeemAgentJobCredential(ctx, tenantID, alive, fresh.ID, fresh.ClaimAttempts, []byte("b"), after); err != nil || !ok {
		t.Fatalf("new holder's redemption refused: ok=%v err=%v", ok, err)
	}
}

// TestClaimHonorsPerRowAgentIdentityDemand is A5's targeting rule at the
// store: an agent.upgrade row names ONE agent, and no other agent may claim it
// however right its roles are. Role says what a machine CAN do; the upgrade
// row says which machine this order is FOR, and a fleet where those blur hands
// agent A the instruction to replace agent B's binary.
func TestClaimHonorsPerRowAgentIdentityDemand(t *testing.T) {
	st, tenantID := newStore(t), tenantA
	ctx := context.Background()
	now := time.Now().UTC()

	target := "cccccccc-0000-0000-0000-000000000001"
	bystander := "cccccccc-0000-0000-0000-000000000002"

	if err := st.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO outbox (tenant_id, destination, payload, idempotency_key, required_agent_id)
			 VALUES ($1, 'agent.upgrade', $2, 'agent-upgrade:c1:1:target', $3::uuid)`,
			tenantID, []byte(`{}`), target)
		return err
	}); err != nil {
		t.Fatalf("seed targeted job: %v", err)
	}

	got, err := st.ClaimAgentJobs(ctx, tenantID, bystander, []string{"agent.upgrade"}, []string{"host", "network"}, 10, time.Minute, now)
	if err != nil {
		t.Fatalf("bystander claim: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("an agent claimed another agent's upgrade job: %v.\n\n"+
			"The first symptom in production would be the WRONG BOX restarting on a new binary", got)
	}

	got, err = st.ClaimAgentJobs(ctx, tenantID, target, []string{"agent.upgrade"}, []string{"host"}, 10, time.Minute, now)
	if err != nil {
		t.Fatalf("target claim: %v", err)
	}
	if len(got) != 1 || got[0].IdempotencyKey != "agent-upgrade:c1:1:target" {
		t.Fatalf("the named agent could not claim its own upgrade: %v", got)
	}
}

// AUD32: effect_lane is the lock name for the estate object being changed.
// A batch claimant must not take both a deploy and rollback for one listener,
// and a second enrolled agent must not take the sibling while the first lease
// is alive. Otherwise "rollback" and "deploy" race and the last writer wins.
func TestAgentJobClaimSerializesOneEffectiveLaneAcrossAgents(t *testing.T) {
	if testing.Short() {
		t.Skip("starts an embedded PostgreSQL; skipped in -short")
	}
	st, tenantID := newStore(t), tenantA
	ctx := context.Background()
	seedAgentJobTenant(t, ctx, st, tenantID)
	const (
		firstAgent  = "dddddddd-0000-0000-0000-000000000001"
		secondAgent = "dddddddd-0000-0000-0000-000000000002"
		lane        = "connector.bind:target:target-a"
	)
	if err := st.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		for i, destination := range []string{"connector.deploy", "connector.rollback"} {
			if _, err := tx.Exec(ctx,
				`INSERT INTO outbox
				        (tenant_id, destination, payload, idempotency_key, effect_lane, required_agent_role, required_agent_id)
				 VALUES ($1, $2, $3, $4, $5, 'host', $6)`,
				tenantID, destination, []byte(`{"target_id":"target-a"}`), "aud32-lane-"+itoa(i), lane, []string{firstAgent, secondAgent}[i]); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("seed same-lane jobs: %v", err)
	}

	now := time.Now().UTC()
	first, err := st.ClaimAgentJobs(ctx, tenantID, firstAgent,
		[]string{"connector.deploy", "connector.rollback"}, []string{"host"}, 10, time.Minute, now)
	if err != nil {
		t.Fatalf("first claim: %v", err)
	}
	if len(first) != 1 {
		t.Fatalf("first agent claimed %d same-lane jobs, want exactly one: %+v", len(first), first)
	}
	second, err := st.ClaimAgentJobs(ctx, tenantID, secondAgent,
		[]string{"connector.deploy", "connector.rollback"}, []string{"host"}, 10, time.Minute, now)
	if err != nil {
		t.Fatalf("second claim: %v", err)
	}
	if len(second) != 0 {
		t.Fatalf("second agent claimed same lane while first lease is active: %+v", second)
	}
}

// The predecessor lives on one machine. Role-compatible is not enough: the
// rollback route must recover the exact enrolled agent that completed the most
// recent host deploy, and the lookup must stay tenant scoped.
func TestLastSuccessfulHostDeployAgentIDIsExactRecentAndTenantScoped(t *testing.T) {
	if testing.Short() {
		t.Skip("starts an embedded PostgreSQL; skipped in -short")
	}
	st := newStore(t)
	ctx := context.Background()
	seedAgentJobTenant(t, ctx, st, tenantA)
	seedAgentJobTenant(t, ctx, st, tenantB)
	const (
		oldAgent   = "eeeeeeee-0000-0000-0000-000000000001"
		newAgent   = "eeeeeeee-0000-0000-0000-000000000002"
		otherAgent = "eeeeeeee-0000-0000-0000-000000000003"
		renewAgent = "eeeeeeee-0000-0000-0000-000000000004"
	)
	seed := func(tenantID, idem, agentID, targetID string, delivered time.Time) {
		t.Helper()
		if err := st.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx,
				`INSERT INTO outbox
				        (tenant_id, destination, payload, idempotency_key, status, delivered_at,
				         required_agent_role, claimed_by_agent_id, claim_expires_at, claim_completed_at)
				 VALUES ($1, 'connector.deploy', $2, $3, 'delivered', $4,
				         'host', $5::uuid, $4, $4)`,
				tenantID, []byte(`{"target_id":"`+targetID+`","identity_id":"identity-`+idem+`","fingerprint":"fingerprint-`+idem+`"}`), idem, delivered, agentID)
			return err
		}); err != nil {
			t.Fatalf("seed delivered deploy: %v", err)
		}
	}
	now := time.Now().UTC()
	seed(tenantA, "aud32-old", oldAgent, "target-a", now.Add(-time.Minute))
	seed(tenantA, "aud32-new", newAgent, "target-a", now)
	seed(tenantB, "aud32-other", otherAgent, "target-a", now.Add(time.Minute))
	var renewalJobID int64
	if err := st.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`INSERT INTO outbox
			        (tenant_id, destination, payload, idempotency_key, status, delivered_at,
			         required_agent_role, claimed_by_agent_id, claim_attempts,
			         claim_expires_at, claim_completed_at)
			 VALUES ($1, 'endpoint.renew', $2, 'aud32-host-renewal', 'delivered', $3,
			         'host', $4::uuid, 3, $3, $3)
			 RETURNING id`, tenantA,
			[]byte(`{"target_id":"target-a","identity_id":"identity-host-renewal"}`),
			now.Add(30*time.Second), renewAgent).Scan(&renewalJobID)
	}); err != nil {
		t.Fatalf("seed delivered host renewal: %v", err)
	}
	if _, err := st.UpsertCertificate(ctx, store.Certificate{
		TenantID: tenantA, Subject: "host-renewal.example.test", Issuer: "test issuer",
		Serial: "renewal-serial", Fingerprint: "fingerprint-host-renewal", Source: "issued",
		IssuanceIdempotencyKey: fmt.Sprintf("agentcsr:%d:3:fixture", renewalJobID),
	}); err != nil {
		t.Fatalf("seed host-renewal certificate: %v", err)
	}

	got, found, err := st.LastSuccessfulHostDeployAgentID(ctx, tenantA, "target-a")
	if err != nil || !found || got != renewAgent {
		t.Fatalf("tenant A exact host = %q found=%v err=%v, want %s", got, found, err, renewAgent)
	}
	evidence, found, err := st.LastSuccessfulHostDeployEvidence(ctx, tenantA, "target-a")
	if err != nil || !found || evidence.AgentID != renewAgent || evidence.IdentityID != "identity-host-renewal" || evidence.Fingerprint != "fingerprint-host-renewal" {
		t.Fatalf("tenant A latest host evidence = %+v found=%v err=%v", evidence, found, err)
	}
	got, found, err = st.LastSuccessfulHostDeployAgentID(ctx, tenantB, "target-a")
	if err != nil || !found || got != otherAgent {
		t.Fatalf("tenant B exact host = %q found=%v err=%v, want %s", got, found, err, otherAgent)
	}
	if _, found, err := st.LastSuccessfulHostDeployAgentID(ctx, tenantA, "missing"); err != nil || found {
		t.Fatalf("missing target found=%v err=%v", found, err)
	}
}
