// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/custody"
	"trstctl.com/trstctl/internal/orchestrator"
)

// Owner decision (batch 14): the credential-rotate playbook waits for the
// replacement's signed, verified delivery before it marks the replacement
// deployed and before it revokes the original. Before, it marked the
// replacement deployed while its delivery was only queued and revoked the
// original at once, so a failed delivery left nothing valid serving.

type rotateRunView struct {
	ID           string   `json:"id"`
	Status       string   `json:"status"`
	Phase        string   `json:"phase"`
	EvidenceRefs []string `json:"evidence_refs"`
	ScopeDelta   struct {
		Replacement string `json:"replacement_identity_id"`
		VerifyBy    string `json:"verify_by"`
	} `json:"scope_delta"`
}

// rotateHostFixture deploys the fixture's host identity with a verified
// report, then starts its rotation, which must leave everything as it was.
func rotateHostFixture(t *testing.T, input map[string]any) (*roleHarness, string, rotateRunView) {
	t.Helper()
	h, _, original := servedHostRevocationFixture(t)
	ctx := t.Context()
	reportHostDelivery(t, h, transport.JobOutcomeVerified)
	assertIdentityStatus(t, h, original, orchestrator.StateDeployed)

	token := seedScopedToken(t, h.store, h.tenant, "incidents:write", "incidents:read", "certs:issue", "identities:write", "identities:read")
	input["target_identity_id"] = original
	status, body := secretsReqKey(t, h.servedHarness, http.MethodPost,
		"/api/v1/remediation/playbooks/credential-rotate/runs", token, "rotate-host", input)
	var run rotateRunView
	if status != http.StatusCreated || json.Unmarshal(body, &run) != nil {
		t.Fatalf("start rotation = %d: %s", status, body)
	}
	if run.Status != orchestrator.RotateRunRunning || run.Phase != orchestrator.RotatePhaseAwaitingVerification || run.ScopeDelta.Replacement == "" {
		t.Fatalf("rotation claimed progress it has not made: %s", body)
	}
	// Nothing is deployed or revoked by the request itself.
	assertIdentityStatus(t, h, original, orchestrator.StateDeployed)
	assertIdentityStatus(t, h, run.ScopeDelta.Replacement, orchestrator.StateIssued)
	assertNoRevocationIntent(t, h, original)
	if err := h.srv.Drain(ctx); err != nil {
		t.Fatalf("drain: %v", err)
	}
	// The drain handed the replacement's issuance to the host agent, and the
	// waiting verification command left the original alone.
	assertIdentityStatus(t, h, original, orchestrator.StateDeployed)
	assertIdentityStatus(t, h, run.ScopeDelta.Replacement, orchestrator.StateIssued)
	assertNoRevocationIntent(t, h, original)
	return h, original, run
}

// reportHostDelivery runs one host job to the given signed outcome.
func reportHostDelivery(t *testing.T, h *roleHarness, outcome string) {
	t.Helper()
	ctx := t.Context()
	job := claimOneRenewal(t, ctx, h)
	key, err := crypto.GenerateHostSubjectKey("mail.revocation.test", []string{"mail.revocation.test"})
	if err != nil {
		t.Fatal(err)
	}
	defer key.Destroy()
	issued, err := h.client.SignJobCSR(ctx, &transport.SignJobCSRRequest{JobID: job.JobID, Attempt: job.Attempt, CSRDER: key.CSRDER})
	if err != nil {
		t.Fatal(err)
	}
	detail, digest := simulatedHostVerification(t, h, job, issued.Fingerprint, outcome)
	id := h.identity.Identity()
	record := custody.Record{Origin: custody.OriginHostAgent, Storage: custody.StorageFile, Exportable: custody.Exportable, GeneratedBy: id.CommonName()}
	report, err := transport.SignedReportWithCustody(id, id.TenantID(), id.CommonName(), job.JobID, job.Attempt,
		outcome, detail, digest, issued.Fingerprint, record, time.Now().UTC().Unix())
	if err != nil {
		t.Fatal(err)
	}
	if result, err := h.client.ReportJobResult(ctx, report); err != nil || !result.Accepted {
		t.Fatalf("host report %s: result=%v err=%v", outcome, result, err)
	}
}

func assertIdentityStatus(t *testing.T, h *roleHarness, identityID string, want orchestrator.State) {
	t.Helper()
	got, err := h.store.GetIdentity(t.Context(), h.tenant, identityID)
	if err != nil || got.Status != string(want) {
		t.Fatalf("identity %s status = %q (%v), want %q", identityID, got.Status, err, want)
	}
}

func assertNoRevocationIntent(t *testing.T, h *roleHarness, identityID string) {
	t.Helper()
	if n := revocationIntents(t, h, identityID); n != 0 {
		t.Fatalf("identity %s has %d revocation intents before its replacement was verified", identityID, n)
	}
}

func revocationIntents(t *testing.T, h *roleHarness, identityID string) int {
	t.Helper()
	var n int
	if err := h.store.SystemPool().QueryRow(t.Context(), `SELECT count(*) FROM outbox WHERE tenant_id = $1
		AND destination = 'revocation.publish' AND convert_from(payload, 'UTF8')::jsonb->>'identity_id' = $2`,
		h.tenant, identityID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// dueRotation makes the run's waiting verification command due now. Only the
// test-owned schedule moves; no clock is changed.
func dueRotation(t *testing.T, h *roleHarness, runID string) {
	t.Helper()
	if err := h.store.WithTenant(t.Context(), h.tenant, func(tx pgx.Tx) error {
		tag, err := tx.Exec(t.Context(), `UPDATE outbox SET next_attempt_at = now() - interval '1 second'
			WHERE tenant_id = $1 AND idempotency_key = $2 AND status = 'pending'`,
			h.tenant, orchestrator.RotateVerificationIdempotencyKey(runID))
		if err == nil && tag.RowsAffected() != 1 {
			t.Fatalf("rotation %s has no pending verification command", runID)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func readRotateRun(t *testing.T, h *roleHarness, runID string) rotateRunView {
	t.Helper()
	run, err := h.store.GetRemediationPlaybookRun(t.Context(), h.tenant, runID)
	if err != nil {
		t.Fatal(err)
	}
	view := rotateRunView{ID: run.ID, Status: run.Status, Phase: run.Phase, EvidenceRefs: run.EvidenceRefs}
	if err := json.Unmarshal(run.ScopeDelta, &view.ScopeDelta); err != nil {
		t.Fatal(err)
	}
	return view
}

func TestServedCredentialRotateRevokesOnlyAfterSignedVerification(t *testing.T) {
	h, original, run := rotateHostFixture(t, map[string]any{"reason": "host key exposed in a build log"})
	ctx := t.Context()
	reportHostDelivery(t, h, transport.JobOutcomeVerified)
	// The host's report delivered and verified the replacement, but the run,
	// not the report, marks it deployed and revokes the original.
	assertIdentityStatus(t, h, run.ScopeDelta.Replacement, orchestrator.StateIssued)
	assertIdentityStatus(t, h, original, orchestrator.StateDeployed)

	dueRotation(t, h, run.ID)
	if err := h.srv.Drain(ctx); err != nil {
		t.Fatalf("drain the verified rotation: %v", err)
	}
	assertIdentityStatus(t, h, run.ScopeDelta.Replacement, orchestrator.StateDeployed)
	assertIdentityStatus(t, h, original, orchestrator.StateRevoked)
	done := readRotateRun(t, h, run.ID)
	if done.Status != orchestrator.RotateRunExecuted || done.Phase != orchestrator.RotatePhaseVerifiedAndRevoked {
		t.Fatalf("verified rotation = %s/%s", done.Status, done.Phase)
	}
	var payload []byte
	if err := h.store.SystemPool().QueryRow(ctx, `SELECT payload FROM outbox WHERE tenant_id = $1
		AND destination = 'revocation.publish' AND convert_from(payload, 'UTF8')::jsonb->>'identity_id' = $2`,
		h.tenant, original).Scan(&payload); err != nil {
		t.Fatalf("the original's revocation intent: %v", err)
	}
	var intent struct {
		Reason string `json:"reason"`
	}
	if err := json.Unmarshal(payload, &intent); err != nil || intent.Reason != "superseded" {
		t.Fatalf("the original's revocation reason = %q (%v), want the playbook default superseded", intent.Reason, err)
	}
	cited := false
	for _, ref := range done.EvidenceRefs {
		if len(ref) > len("verification:") && ref[:len("verification:")] == "verification:" {
			cited = true
		}
	}
	if !cited {
		t.Fatalf("the executed run does not cite its signed verification: %v", done.EvidenceRefs)
	}
}

func TestServedCredentialRotateKeepsTheOriginalWithoutVerification(t *testing.T) {
	for _, tc := range []struct {
		name, outcome, phase string
	}{
		{"deadline", "", orchestrator.RotatePhaseUnverifiedKept},
		{"verify_failed", transport.JobOutcomeVerifyFailed, orchestrator.RotatePhaseVerifyFailedKept},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, original, run := rotateHostFixture(t, map[string]any{"reason": "host key exposed", "verification_timeout_seconds": 300})
			ctx := t.Context()
			if tc.outcome != "" {
				reportHostDelivery(t, h, tc.outcome)
			} else {
				verifyBy, err := time.Parse(time.RFC3339, run.ScopeDelta.VerifyBy)
				if err != nil {
					t.Fatal(err)
				}
				d := h.srv.obHandler.(*issuanceDispatcher)
				d.rotateNow = func() time.Time { return verifyBy.Add(time.Second) }
			}
			for range 2 { // a retried command changes nothing
				dueRotationIfPending(t, h, run.ID)
				if err := h.srv.Drain(ctx); err != nil {
					t.Fatalf("drain: %v", err)
				}
			}
			kept := readRotateRun(t, h, run.ID)
			if kept.Status != orchestrator.RotateRunFailed || kept.Phase != tc.phase {
				t.Fatalf("unverified rotation = %s/%s, want failed/%s", kept.Status, kept.Phase, tc.phase)
			}
			assertIdentityStatus(t, h, original, orchestrator.StateDeployed)
			assertIdentityStatus(t, h, run.ScopeDelta.Replacement, orchestrator.StateIssued)
			assertNoRevocationIntent(t, h, original)
			var findings int
			var meta []byte
			if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
				if err := tx.QueryRow(ctx, `SELECT count(*) FROM discovery_findings WHERE tenant_id = $1 AND kind = $2`,
					h.tenant, orchestrator.RotationUnverifiedFindingKind).Scan(&findings); err != nil {
					return err
				}
				return tx.QueryRow(ctx, `SELECT metadata FROM discovery_findings WHERE tenant_id = $1 AND kind = $2`,
					h.tenant, orchestrator.RotationUnverifiedFindingKind).Scan(&meta)
			}); err != nil || findings != 1 {
				t.Fatalf("unverified rotation findings = %d (%v), want 1", findings, err)
			}
			var finding struct {
				Replacement string `json:"replacement_identity_id"`
				Original    string `json:"original_identity_id"`
				Target      string `json:"target"`
				Outcome     string `json:"outcome"`
			}
			if err := json.Unmarshal(meta, &finding); err != nil || finding.Replacement != run.ScopeDelta.Replacement ||
				finding.Original != original || finding.Target == "" || finding.Outcome != tc.phase {
				t.Fatalf("the finding does not name the replacement and its target: %s", meta)
			}
		})
	}
}

// dueRotationIfPending moves a still-pending command; a terminal run's
// command is already delivered.
func dueRotationIfPending(t *testing.T, h *roleHarness, runID string) {
	t.Helper()
	if err := h.store.WithTenant(t.Context(), h.tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(t.Context(), `UPDATE outbox SET next_attempt_at = now() - interval '1 second'
			WHERE tenant_id = $1 AND idempotency_key = $2 AND status = 'pending'`,
			h.tenant, orchestrator.RotateVerificationIdempotencyKey(runID))
		return err
	}); err != nil {
		t.Fatal(err)
	}
}
