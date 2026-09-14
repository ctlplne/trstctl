// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/events"
)

// Signed job receipts, proven on the assembled binary (epic A1, acceptance #2).
//
// mTLS already proves who is on the connection, so the question these tests
// actually answer is what a SIGNATURE adds. It adds evidence that outlives the
// connection: after the session ends, "agent-7 executed this deploy" is either
// a sentence the control plane wrote about itself — which anyone with write
// access to the event store could also write — or it is a statement the agent
// signed with a key the control plane does not hold. These prove it is the
// second, and prove that everything which is not the second is refused.

// A receipt with no signature is refused, and the refusal is recorded.
//
// This is the case that decides whether the signature is a security control or
// a decoration. If an unsigned report still lands, then an attacker who reaches
// the channel simply omits the field, and every signed receipt beside it proves
// nothing about the ones that are missing.
func TestServedChannelRefusesAnUnsignedJobReceipt(t *testing.T) {
	ctx := context.Background()
	h := agentJobHarness(t, "connector.deploy")
	seedClaimableJob(t, ctx, h, "connector.deploy", "deploy:unsigned-1")

	claimed, err := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{Kinds: []string{"connector.deploy"}, Limit: 1})
	if err != nil || len(claimed.Jobs) != 1 {
		t.Fatalf("claim: %d jobs (err %v)", len(claimed.Jobs), err)
	}
	job := claimed.Jobs[0]

	_, err = h.client.ReportJobResult(ctx, &transport.ReportJobResultRequest{
		JobID: job.JobID, Outcome: transport.JobOutcomeExecuted, Attempt: job.Attempt,
	})
	if err == nil {
		t.Fatal("an unsigned receipt was accepted; the signature is not a gate")
	}
	assertReceiptRejected(t, ctx, h, job.JobID, "unsigned")

	// The job is untouched: a refused receipt must not close the claim, or a
	// forger could complete work by sending a report nobody can verify.
	assertJobNotCompleted(t, ctx, h, job.JobID)
}

// A receipt signed by a DIFFERENT agent's key is refused on this connection.
//
// This is the forgery case and the cross-tenant case at once, because they are
// the same check: the server rebuilds the statement from the certificate that
// authenticated, so a signature made by any other key is over different bytes
// than the ones being verified.
func TestServedChannelRefusesAReceiptSignedByAnotherAgent(t *testing.T) {
	ctx := context.Background()
	h := agentJobHarness(t, "connector.deploy")
	seedClaimableJob(t, ctx, h, "connector.deploy", "deploy:forged-1")

	claimed, err := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{Kinds: []string{"connector.deploy"}, Limit: 1})
	if err != nil || len(claimed.Jobs) != 1 {
		t.Fatalf("claim: %d jobs (err %v)", len(claimed.Jobs), err)
	}
	job := claimed.Jobs[0]

	// A second, legitimately enrolled agent in the SAME tenant. It holds a
	// valid certificate from the same CA — it is not an outsider — and it still
	// cannot sign for work claimed on another agent's connection.
	other := enrollAgent(t, h.servedHarness, "job-agent-impostor", "agent.trstctl.local")
	forged := signedJobReport(t, other, job.JobID, job.Attempt, transport.JobOutcomeExecuted, "", "")
	// Everything else about the request is exactly what the real agent would
	// send. Only the signing key differs.
	if _, err := h.client.ReportJobResult(ctx, forged); err == nil {
		t.Fatal("a receipt signed by another agent was accepted")
	}
	assertReceiptRejected(t, ctx, h, job.JobID, "signature")
	assertJobNotCompleted(t, ctx, h, job.JobID)
}

// A receipt whose statement was tampered with after signing is refused.
//
// The signature covers the outcome. Flipping "failed" to "executed" in flight
// is the attack that matters most — it is how a deploy that never happened
// becomes a deploy the ledger believes in.
func TestServedChannelRefusesATamperedOutcome(t *testing.T) {
	ctx := context.Background()
	h := agentJobHarness(t, "connector.deploy")
	seedClaimableJob(t, ctx, h, "connector.deploy", "deploy:tampered-1")

	claimed, err := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{Kinds: []string{"connector.deploy"}, Limit: 1})
	if err != nil || len(claimed.Jobs) != 1 {
		t.Fatalf("claim: %d jobs (err %v)", len(claimed.Jobs), err)
	}
	job := claimed.Jobs[0]

	req := h.report(t, job.JobID, job.Attempt, transport.JobOutcomeFailed, "the appliance refused", "")
	req.Outcome = transport.JobOutcomeExecuted // the tamper
	if _, err := h.client.ReportJobResult(ctx, req); err == nil {
		t.Fatal("a receipt whose outcome was changed after signing was accepted")
	}
	assertReceiptRejected(t, ctx, h, job.JobID, "signature")
	assertJobNotCompleted(t, ctx, h, job.JobID)
}

// A valid receipt captured and replayed later is refused on its timestamp.
//
// A signature does not expire on its own. Without a bound, a receipt captured
// once is a permanently valid "this deploy succeeded" that can be replayed
// against any future attempt of the same job.
func TestServedChannelRefusesAStaleReceipt(t *testing.T) {
	ctx := context.Background()
	h := agentJobHarness(t, "connector.deploy")
	seedClaimableJob(t, ctx, h, "connector.deploy", "deploy:stale-1")

	claimed, err := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{Kinds: []string{"connector.deploy"}, Limit: 1})
	if err != nil || len(claimed.Jobs) != 1 {
		t.Fatalf("claim: %d jobs (err %v)", len(claimed.Jobs), err)
	}
	job := claimed.Jobs[0]

	// Signed properly, an hour ago. Every byte verifies; only the clock says no.
	id := h.agent.Identity()
	stale, err := transport.SignedReport(id, id.TenantID(), id.CommonName(),
		job.JobID, job.Attempt, transport.JobOutcomeExecuted, "", "",
		time.Now().UTC().Add(-time.Hour).Unix())
	if err != nil {
		t.Fatalf("sign stale receipt: %v", err)
	}
	if _, err := h.client.ReportJobResult(ctx, stale); err == nil {
		t.Fatal("a receipt signed an hour ago was accepted")
	}
	assertReceiptRejected(t, ctx, h, job.JobID, "issued-at")
	assertJobNotCompleted(t, ctx, h, job.JobID)
}

// An accepted receipt is stored with the event, and what is stored verifies.
//
// A receipt that is checked and then discarded gives an auditor nothing: they
// would have to trust the server's assertion that it once verified something.
// This walks the whole path an auditor would — read the event, take the stored
// statement and signature, verify them against the agent's certificate — and
// it uses the same verification the server uses, so a change that broke one
// would break the other.
func TestAnAcceptedReceiptIsStoredAndIndependentlyVerifiable(t *testing.T) {
	ctx := context.Background()
	h := agentJobHarness(t, "connector.deploy")
	seedClaimableJob(t, ctx, h, "connector.deploy", "deploy:verifiable-1")

	claimed, err := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{Kinds: []string{"connector.deploy"}, Limit: 1})
	if err != nil || len(claimed.Jobs) != 1 {
		t.Fatalf("claim: %d jobs (err %v)", len(claimed.Jobs), err)
	}
	job := claimed.Jobs[0]

	accepted, err := h.client.ReportJobResult(ctx,
		h.report(t, job.JobID, job.Attempt, transport.JobOutcomeExecuted, "", "sha256:transcript"))
	if err != nil {
		t.Fatalf("report: %v", err)
	}
	if !accepted.Accepted {
		t.Fatal("a correctly signed report from the holder was refused")
	}

	statement, signature := storedReceipt(t, ctx, h, "agent.job.executed", job.JobID)
	if statement == "" || len(signature) == 0 {
		t.Fatal("the executed event carries no receipt; the signature was verified and thrown away")
	}

	// The auditor's check: this is the agent's certificate, and this is the
	// signature over these exact bytes.
	leafDER := h.agent.Identity().CertificateDER()
	if err := mtls.VerifyStatement(leafDER, []byte(statement), signature); err != nil {
		t.Fatalf("the stored receipt does not verify against the agent's certificate: %v", err)
	}

	// And the stored statement says what the event says. A receipt that
	// verifies but describes a different job would be worse than no receipt: it
	// would read as proof of something it does not cover.
	for _, want := range []string{
		"tenant=" + h.tenant,
		"agent=" + h.agent.Identity().CommonName(),
		"outcome=" + transport.JobOutcomeExecuted,
		"evidence=sha256:transcript",
	} {
		if !strings.Contains(statement, want) {
			t.Errorf("stored receipt statement is missing %q:\n%s", want, statement)
		}
	}
}

// jobEvents replays the log and returns the decoded payloads of one event type
// for one job. Events are read the way the product reads them — through the
// log — rather than by querying a table, so a test cannot pass against a schema
// the running code does not use.
func jobEvents(t *testing.T, h *agentChannelHarness, eventType string, jobID int64) []map[string]any {
	t.Helper()
	var out []map[string]any
	if err := h.log.Replay(context.Background(), 0, func(e events.Event) error {
		if e.Type != eventType || e.TenantID != h.tenant {
			return nil
		}
		var payload map[string]any
		if err := json.Unmarshal(e.Data, &payload); err != nil {
			return nil
		}
		if id, ok := payload["job_id"].(float64); !ok || int64(id) != jobID {
			return nil
		}
		out = append(out, payload)
		return nil
	}); err != nil {
		t.Fatalf("replay events: %v", err)
	}
	return out
}

// assertReceiptRejected checks that the refusal was recorded as an audit event
// with the reason. A rejection nobody can see is indistinguishable from a
// network error, and the operator whose agent is being refused needs to know.
func assertReceiptRejected(t *testing.T, ctx context.Context, h *agentChannelHarness, jobID int64, wantReason string) {
	t.Helper()
	_ = ctx
	var reasons []string
	for _, payload := range jobEvents(t, h, "agent.job.receipt.rejected", jobID) {
		reason, _ := payload["reason"].(string)
		reasons = append(reasons, reason)
		if strings.Contains(reason, wantReason) {
			return
		}
	}
	t.Errorf("no agent.job.receipt.rejected event mentioning %q for job %d; recorded reasons: %v",
		wantReason, jobID, reasons)
}

// assertJobNotCompleted proves a refused receipt left the work alone.
func assertJobNotCompleted(t *testing.T, ctx context.Context, h *agentChannelHarness, jobID int64) {
	t.Helper()
	var completed bool
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT status = 'delivered' FROM outbox WHERE tenant_id = $1 AND id = $2`,
			h.tenant, jobID).Scan(&completed)
	}); err != nil {
		t.Fatalf("read job status: %v", err)
	}
	if completed {
		t.Error("a refused receipt completed the job anyway — the work is recorded as done " +
			"on the strength of a report the server would not accept")
	}
}

// storedReceipt reads the receipt an event carries.
func storedReceipt(t *testing.T, ctx context.Context, h *agentChannelHarness, eventType string, jobID int64) (string, []byte) {
	t.Helper()
	_ = ctx
	found := jobEvents(t, h, eventType, jobID)
	if len(found) == 0 {
		t.Fatalf("no %s event for job %d", eventType, jobID)
	}
	payload := found[len(found)-1]
	statement, _ := payload["receipt_statement"].(string)
	encoded, _ := payload["receipt_signature"].(string)
	if encoded == "" {
		return statement, nil
	}
	sig, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("decode stored receipt signature: %v", err)
	}
	return statement, sig
}

// The Operations surface reports refused receipts.
//
// A receipt gate that only writes to an event stream is a gate nobody watches.
// This drives the served route the console reads, after a real refusal, and
// asserts the number an operator would see — because "it is in the event log"
// and "an operator will notice" are different claims and only the second one
// matters at 3am.
func TestOperationsJobPostureReportsRefusedReceipts(t *testing.T) {
	ctx := context.Background()
	h := agentJobHarness(t, "connector.deploy")
	seedClaimableJob(t, ctx, h, "connector.deploy", "deploy:posture-1")

	claimed, err := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{Kinds: []string{"connector.deploy"}, Limit: 1})
	if err != nil || len(claimed.Jobs) != 1 {
		t.Fatalf("claim: %d jobs (err %v)", len(claimed.Jobs), err)
	}
	job := claimed.Jobs[0]

	before, err := h.srv.agentJobPosture(ctx)
	if err != nil {
		t.Fatalf("read job posture: %v", err)
	}

	// One refusal, of the kind a drifting clock produces.
	id := h.agent.Identity()
	stale, err := transport.SignedReport(id, id.TenantID(), id.CommonName(),
		job.JobID, job.Attempt, transport.JobOutcomeExecuted, "", "",
		time.Now().UTC().Add(-2*time.Hour).Unix())
	if err != nil {
		t.Fatalf("sign stale receipt: %v", err)
	}
	if _, err := h.client.ReportJobResult(ctx, stale); err == nil {
		t.Fatal("the stale receipt was accepted")
	}

	after, err := h.srv.agentJobPosture(ctx)
	if err != nil {
		t.Fatalf("read job posture after refusal: %v", err)
	}
	if after.Receipts.Rejected <= before.Receipts.Rejected {
		t.Fatalf("refused receipts on the operations surface: %d before, %d after — a refusal "+
			"that does not move this number is a refusal no operator will see",
			before.Receipts.Rejected, after.Receipts.Rejected)
	}
	// The reason has to say WHICH failure it was. "Something was refused" sends
	// an operator to check certificates when the answer is a clock.
	if !strings.Contains(after.Receipts.LastRejectedReason, "issued-at") {
		t.Errorf("last refusal reason = %q, want it to name the issued-at window",
			after.Receipts.LastRejectedReason)
	}
	if after.Receipts.LastRejectedAt == nil {
		t.Error("last refusal has no timestamp; an operator cannot tell an ongoing problem from an old one")
	}

	// And a good receipt moves the other number, so a clean fabric is
	// distinguishable from one where nothing is being reported at all.
	good, err := h.client.ReportJobResult(ctx,
		h.report(t, job.JobID, job.Attempt, transport.JobOutcomeExecuted, "", ""))
	if err != nil {
		t.Fatalf("good report: %v", err)
	}
	if !good.Accepted {
		t.Fatal("a correctly signed report from the claim holder was refused")
	}
	final, err := h.srv.agentJobPosture(ctx)
	if err != nil {
		t.Fatalf("read job posture after success: %v", err)
	}
	if final.Receipts.Verified <= after.Receipts.Verified {
		t.Errorf("verified receipts: %d before, %d after a good report", after.Receipts.Verified, final.Receipts.Verified)
	}
}

// A refusal for a job the agent never claimed is audited but not counted.
//
// The two records answer different questions and must not be conflated. The
// audit event answers "what happened on this channel", and it takes everything
// unconditionally. The Operations counter answers "how much refused work is out
// there", and an enrolled agent naming job ids it never held could otherwise
// fill that number with work that does not exist — which would make the one
// signal an operator is supposed to trust the easiest one to poison.
func TestARefusalForUnclaimedWorkIsAuditedButNotCounted(t *testing.T) {
	ctx := context.Background()
	h := agentJobHarness(t, "connector.deploy")

	before, err := h.srv.agentJobPosture(ctx)
	if err != nil {
		t.Fatalf("read job posture: %v", err)
	}

	// A job id this agent has never seen, reported unsigned.
	const fabricated int64 = 987654321
	if _, err := h.client.ReportJobResult(ctx, &transport.ReportJobResultRequest{
		JobID: fabricated, Outcome: transport.JobOutcomeExecuted,
	}); err == nil {
		t.Fatal("an unsigned receipt for unclaimed work was accepted")
	}

	// Audited: the channel event took it.
	assertReceiptRejected(t, ctx, h, fabricated, "unsigned")

	// Not counted: the operator's number still describes real work.
	after, err := h.srv.agentJobPosture(ctx)
	if err != nil {
		t.Fatalf("read job posture after: %v", err)
	}
	if after.Receipts.Rejected != before.Receipts.Rejected {
		t.Errorf("refused-receipt count moved from %d to %d for a job nobody claimed; "+
			"the counter an operator reads can be inflated by naming job ids",
			before.Receipts.Rejected, after.Receipts.Rejected)
	}
}

// A rollback the agent refused before contact must not be recorded as contact.
//
// The served status vocabulary declares ContactedTarget on the generic failure
// status, so recording a pre-flight refusal there would tell an operator the
// appliance rejected something it never heard about — and send them to check an
// appliance that is fine while a bad certificate keeps serving.
func TestRollbackContactClassificationMatchesWhatTheRelayDid(t *testing.T) {
	t.Parallel()
	refusedBeforeContact := []string{
		transport.RollbackRefusedBadPayload,
		transport.RollbackRefusedNotExecutable,
		transport.RollbackRefusedCannotRebind,
		transport.RollbackRefusedNoPredecessor,
		transport.RollbackRefusedNoCredential,
		transport.RollbackRefusedNoLockedMemory,
		transport.RollbackRefusedNoHostRestore,
		transport.RollbackRefusedNoHostState,
		transport.RollbackRefusedNoHostProfile,
		transport.RollbackRefusedHostPredecessorMissing,
		transport.RollbackRefusedHostStateUnavailable,
		transport.RollbackRefusedCapability,
	}
	for _, reason := range refusedBeforeContact {
		if transport.RollbackReasonContactedTarget(reason) {
			t.Errorf("reason %q is a local refusal but classifies as having contacted the target", reason)
		}
	}
	reachedTarget := []string{
		transport.RollbackFailedPredecessorGone,
		transport.RollbackFailedAtTarget,
	}
	for _, reason := range reachedTarget {
		if !transport.RollbackReasonContactedTarget(reason) {
			t.Errorf("reason %q means the agent reached the target but classifies as no contact", reason)
		}
	}
	// An unknown phrase — a newer or older agent — must fail closed to NO
	// contact. Asserting contact we cannot substantiate is the failure this
	// classification exists to prevent.
	if transport.RollbackReasonContactedTarget("something a future agent says") {
		t.Error("an unrecognized reason asserted contact; it must fail closed")
	}
}

// Relay-executed work must survive the control plane's own outbox sweep.
//
// This is the defect that made D4 non-functional end to end and had already
// made D5's connector.test non-functional in production without anyone
// noticing. The control plane sweeps every "connector." outbox row and does not
// filter on required_agent_role, so a destination with no dispatcher case hits
// the default branch, burns its attempt budget on a hard error, and lands in
// status='failed'. ClaimAgentJobs requires status='pending', so the row becomes
// permanently invisible to the relay that was supposed to execute it — while
// the API has already told the operator it is queued.
//
// Nothing failed anywhere. Every unit test passed, because none of them ran the
// control-plane dispatcher and the relay claim path against the same row.
func TestRelayExecutedWorkSurvivesTheControlPlaneDispatcher(t *testing.T) {
	ctx := context.Background()
	for _, destination := range []string{"connector.rollback", "connector.test"} {
		t.Run(destination, func(t *testing.T) {
			h := agentJobHarness(t, destination)
			seedRelayExecutedJob(t, ctx, h, destination, "dispatcher-survives:"+destination)

			// The real dispatcher and the real handler — not a stand-in. A test
			// with its own handler could not see this defect, because the
			// defect IS which destinations the production handler recognizes.
			if _, err := h.srv.outbox.Dispatch(ctx, h.srv.obHandler); err != nil {
				t.Fatalf("dispatch: %v", err)
			}

			// The precise property, not a proxy for it: the dispatcher must not
			// consume an ATTEMPT. Asserting only that the row is still
			// claimable proves nothing here — retry backoff keeps a row pending
			// long after the first failure, so a hard error looks identical to a
			// correct deferral until the budget finally runs out in production,
			// hours later, with the operator already told the work was queued.
			var status string
			var attempts int
			var lastError string
			if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
				return tx.QueryRow(ctx,
					`SELECT status, attempts, COALESCE(last_error, '') FROM outbox
					  WHERE tenant_id = $1 AND destination = $2`,
					h.tenant, destination).Scan(&status, &attempts, &lastError)
			}); err != nil {
				t.Fatalf("read outbox row: %v", err)
			}
			if attempts != 0 {
				t.Errorf("the control-plane dispatcher consumed %d attempt(s) on %s (last_error %q); "+
					"work only a relay can execute must be deferred without burning the budget, or "+
					"the row dead-letters into status='failed' where ClaimAgentJobs can never see it",
					attempts, destination, lastError)
			}
			if status != "pending" {
				t.Errorf("%s row is %q after the control-plane dispatcher ran, want pending", destination, status)
			}

			// And it is still claimable by the agent that should run it.
			claimed, err := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{
				Kinds: []string{destination}, Limit: 1,
			})
			if err != nil {
				t.Fatalf("claim: %v", err)
			}
			if len(claimed.Jobs) != 1 {
				t.Fatalf("%s was not claimable after the control-plane dispatcher ran: the "+
					"dispatcher consumed work only a relay can execute, and the operator was "+
					"already told it was queued", destination)
			}
		})
	}
}

// seedRelayExecutedJob enqueues a row a relay could genuinely execute, so the
// claim path's envelope projection accepts it. A placeholder payload would be
// refused by projectRollbackIntent and the test would fail for the wrong reason.
func seedRelayExecutedJob(t *testing.T, ctx context.Context, h *agentChannelHarness, destination, idemKey string) {
	t.Helper()
	payload := []byte(`{"connector":"f5","target":"edge-1","target_config":{"endpoint":"https://f5.example.internal"}}`)
	if destination == "connector.rollback" {
		// Claim-time revocation authorization needs the exact predecessor in
		// inventory. Import a real signed fixture; do not bypass that safety gate.
		pem := servedHealthLeafPEM(t, h.servedHarness, "rollback.dispatcher.test", 24*time.Hour)
		token := seedScopedToken(t, h.store, h.tenant, "certs:write")
		ingestServedHealthCertificate(t, h.servedHarness, token, idemKey+":predecessor", pem, "import", "f5:/Common/edge-1")
		info, err := certinfo.Inspect([]byte(pem))
		if err != nil {
			t.Fatal(err)
		}
		payload, err = json.Marshal(map[string]any{
			"connector": "f5", "target": "edge-1", "predecessor_fingerprint": info.SHA256Fingerprint,
			"predecessor_serial": info.SerialNumber, "target_config": map[string]string{"endpoint": "https://f5.example.internal"},
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := h.store.CheckConnectorRollbackPayload(ctx, h.tenant, payload); err != nil {
			t.Fatalf("rollback prerequisite is not authorized: %v", err)
		}
	}
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO outbox (tenant_id, destination, payload, idempotency_key)
			 VALUES ($1, $2, $3, $4)`,
			h.tenant, destination, payload, idemKey)
		return err
	}); err != nil {
		t.Fatalf("seed relay-executed job: %v", err)
	}
}
