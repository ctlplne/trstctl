// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

func resolutionFindingID(n int) string { return fmt.Sprintf("a1060000-0000-4000-8000-%012d", n) }

type resolvedFinding struct {
	ID                string     `json:"id"`
	TriageStatus      string     `json:"triage_status"`
	TriageActor       string     `json:"triage_actor"`
	TriageAssignee    string     `json:"triage_assignee"`
	TriageDueAt       *time.Time `json:"triage_due_at"`
	TriageEvidenceRef string     `json:"triage_evidence_ref"`
	RiskAcceptedUntil *time.Time `json:"risk_accepted_until"`
	Regressed         bool       `json:"regressed"`
}

// A106: a posture finding is investigated (an assignee and a due date),
// recorded remediated (the evidence of the fix), its risk accepted until a
// time, or reopened. Each action takes only its own fields. The CT dashboard
// counts every resolution; the NHI posture leaves a remediation that held and
// an unexpired acceptance out of the open posture and counts them, and takes a
// remediation seen again after its fix back in. The leader's sweep reopens an
// expired acceptance once, as the system.
func TestServedFindingResolutionWorkflow(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	ctx := t.Context()
	now := time.Now().UTC()
	ctSource, nhiSource := resolutionFindingID(901), resolutionFindingID(902)
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		for n, src := range []struct{ id, kind string }{{ctSource, "ct_log"}, {nhiSource, "nhi"}} {
			if err := h.store.ApplyDiscoverySourceUpsertedTx(ctx, tx, store.DiscoverySource{ID: src.id, TenantID: h.tenant, Kind: src.kind,
				Name: "a106-" + src.kind, Config: []byte(`{}`), CreatedAt: now, UpdatedAt: now}); err != nil {
				return err
			}
			runID := resolutionFindingID(950 + n)
			if err := h.store.ApplyDiscoveryRunQueuedTx(ctx, tx, store.DiscoveryRun{ID: runID, TenantID: h.tenant, SourceID: src.id, Status: "queued", CreatedAt: now}); err != nil {
				return err
			}
			kind, meta := "ct_unexpected_issuance", `{}`
			if src.kind == "nhi" {
				kind, meta = "non_human_identity", `{"display_name":"svc-a106"}`
			}
			for i := 0; i < 3; i++ {
				id := resolutionFindingID(1000*(n+1) + i)
				if err := h.store.ApplyDiscoveryFindingRecordedTx(ctx, tx, store.DiscoveryFinding{ID: id, TenantID: h.tenant, RunID: runID,
					SourceID: src.id, Kind: kind, Ref: "ref-" + id, Provenance: "a106", Fingerprint: "fp-" + id, RiskScore: 70,
					Metadata: []byte(meta), DiscoveredAt: now}); err != nil {
					return err
				}
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("seed findings: %v", err)
	}
	writer := seedScopedToken(t, h.store, h.tenant, "discovery:read", "discovery:write", "nhi:read")
	resolve := func(id, key string, body map[string]any) (int, resolvedFinding) {
		t.Helper()
		status, raw := secretsReqKey(t, h, http.MethodPost, "/api/v1/discovery/findings/"+id+"/resolution", writer, key, body)
		var out resolvedFinding
		if status == http.StatusOK {
			if err := json.Unmarshal(raw, &out); err != nil {
				t.Fatalf("resolution body %s: %v", raw, err)
			}
		}
		return status, out
	}
	in := func(d time.Duration) string { return now.Add(d).Format(time.RFC3339) }
	ct0, ct1, ct2 := resolutionFindingID(1000), resolutionFindingID(1001), resolutionFindingID(1002)

	// Investigate, then reassign with a later due date.
	if status, f := resolve(ct0, "a106-1", map[string]any{"action": "investigate", "reason": "unexpected issuer", "assignee": "pki-oncall", "due_at": in(2 * time.Hour)}); status != http.StatusOK ||
		f.TriageStatus != "investigating" || f.TriageAssignee != "pki-oncall" || f.TriageDueAt == nil {
		t.Fatalf("investigate = %d %+v", status, f)
	}
	if status, f := resolve(ct0, "a106-2", map[string]any{"action": "investigate", "reason": "handed over", "assignee": "pki-lead", "due_at": in(4 * time.Hour)}); status != http.StatusOK ||
		f.TriageAssignee != "pki-lead" || !f.TriageDueAt.After(now.Add(3*time.Hour)) {
		t.Fatalf("reassign = %d %+v", status, f)
	}
	for _, bad := range []map[string]any{
		{"action": "investigate", "reason": "x", "assignee": "a", "due_at": in(-time.Hour)},
		{"action": "investigate", "reason": "x"},
		{"action": "investigate", "reason": "x", "assignee": "a", "evidence_ref": "CHG-1"},
		{"action": "remediated", "reason": "x"},
		{"action": "accept_risk", "reason": "x"},
		{"action": "accept_risk", "reason": "x", "expires_at": in(400 * 24 * time.Hour)},
		{"action": "close", "reason": "x"},
		{"action": "reopen"},
	} {
		if status, _ := resolve(ct1, fmt.Sprint("a106-bad-", bad), bad); status != http.StatusBadRequest {
			t.Fatalf("resolution %v = %d, want 400", bad, status)
		}
	}
	// Remediated with evidence, reopened, then its risk accepted for a day.
	if status, f := resolve(ct1, "a106-3", map[string]any{"action": "remediated", "reason": "issuer revoked the leaf", "evidence_ref": "CHG-4411"}); status != http.StatusOK ||
		f.TriageStatus != "remediated" || f.TriageEvidenceRef != "CHG-4411" {
		t.Fatalf("remediated = %d %+v", status, f)
	}
	if status, f := resolve(ct1, "a106-4", map[string]any{"action": "reopen", "reason": "the issuer reissued it"}); status != http.StatusOK || f.TriageStatus != "unmanaged" || f.TriageEvidenceRef != "" {
		t.Fatalf("reopen = %d %+v", status, f)
	}
	if status, f := resolve(ct2, "a106-5", map[string]any{"action": "accept_risk", "reason": "partner CA under contract", "expires_at": in(24 * time.Hour)}); status != http.StatusOK ||
		f.TriageStatus != "accepted_risk" || f.RiskAcceptedUntil == nil {
		t.Fatalf("accept risk = %d %+v", status, f)
	}
	if status, _ := resolve(ct2, "a106-6", map[string]any{"action": "remediated", "reason": "x", "evidence_ref": "CHG-1"}); status != http.StatusOK {
		t.Fatalf("an accepted risk can still be fixed: %d", status)
	}
	if status, _ := resolve(ct2, "a106-7", map[string]any{"action": "accept_risk", "reason": "x", "expires_at": in(time.Hour)}); status != http.StatusConflict {
		t.Fatalf("accepting a remediated finding's risk = %d, want 409 (reopen it first)", status)
	}

	var ct struct {
		Summary struct {
			FindingCount       int `json:"finding_count"`
			OpenFindingCount   int `json:"open_finding_count"`
			InvestigatingCount int `json:"investigating_count"`
			RemediatedCount    int `json:"remediated_count"`
			AcceptedRiskCount  int `json:"accepted_risk_count"`
		} `json:"summary"`
	}
	if status, body := secretsReq(t, h, http.MethodGet, "/api/v1/discovery/ct-monitoring", writer, nil); status != http.StatusOK || json.Unmarshal(body, &ct) != nil ||
		ct.Summary.FindingCount != 3 || ct.Summary.OpenFindingCount != 1 || ct.Summary.InvestigatingCount != 1 || ct.Summary.RemediatedCount != 1 {
		t.Fatalf("CT dashboard after resolutions = %d %s", status, body)
	}
	// Overdue is counted against the tally's clock.
	tallies, err := h.store.TallyDiscoveryFindings(ctx, h.tenant, store.DiscoveryFindingFilter{SourceKind: "ct_log"}, now.Add(5*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	overdue := 0
	for _, tally := range tallies {
		overdue += tally.Overdue
	}
	if overdue != 1 {
		t.Fatalf("overdue investigations five hours on = %d, want 1", overdue)
	}

	// NHI posture: an accepted risk and a held remediation leave the open posture.
	nhi0, nhi1 := resolutionFindingID(2000), resolutionFindingID(2001)
	if status, _ := resolve(nhi0, "a106-8", map[string]any{"action": "accept_risk", "reason": "vendor sunset in Q1", "expires_at": in(time.Hour)}); status != http.StatusOK {
		t.Fatalf("accept NHI risk = %d", status)
	}
	if status, _ := resolve(nhi1, "a106-9", map[string]any{"action": "remediated", "reason": "credential rotated", "evidence_ref": "CHG-7"}); status != http.StatusOK {
		t.Fatalf("remediate NHI = %d", status)
	}
	shadow := func() (findings, accepted, remediated int) {
		t.Helper()
		status, body := secretsReq(t, h, http.MethodGet, "/api/v1/nhi/posture/shadow", writer, nil)
		var out struct {
			Summary struct {
				Findings     int `json:"findings"`
				AcceptedRisk int `json:"accepted_risk"`
				Remediated   int `json:"remediated"`
			} `json:"summary"`
		}
		if status != http.StatusOK || json.Unmarshal(body, &out) != nil {
			t.Fatalf("shadow posture = %d %s", status, body)
		}
		return out.Summary.Findings, out.Summary.AcceptedRisk, out.Summary.Remediated
	}
	// The shadow posture reads every discovery finding: open are CT ct0
	// (investigating) and ct1 (reopened) and NHI nhi2; ct2 and nhi1 are
	// remediated; nhi0 is accepted.
	if findings, accepted, remediated := shadow(); findings != 3 || accepted != 1 || remediated != 2 {
		t.Fatalf("shadow posture after resolutions: findings=%d accepted=%d remediated=%d", findings, accepted, remediated)
	}
	// The remediated NHI is seen again after its fix: it regressed and is open.
	if _, err := h.store.SystemPool().Exec(ctx, `UPDATE discovery_findings SET last_seen_at = triaged_at + interval '1 minute' WHERE tenant_id=$1 AND id=$2`, h.tenant, nhi1); err != nil {
		t.Fatal(err)
	}
	if findings, _, remediated := shadow(); findings != 4 || remediated != 1 {
		t.Fatalf("shadow posture after the remediation regressed: findings=%d remediated=%d", findings, remediated)
	}

	// The sweep reopens the expired acceptance once, as the system.
	later := now.Add(2 * time.Hour)
	if n, err := h.srv.orch.ExpireRiskAcceptances(ctx, h.tenant, later); err != nil || n != 1 {
		t.Fatalf("expiry sweep reopened %d (%v), want the NHI acceptance", n, err)
	}
	if n, err := h.srv.orch.ExpireRiskAcceptances(ctx, h.tenant, later); err != nil || n != 0 {
		t.Fatalf("second expiry sweep reopened %d (%v)", n, err)
	}
	reopened, err := h.store.GetDiscoveryFinding(ctx, h.tenant, nhi0)
	if err != nil || reopened.TriageStatus != "unmanaged" || reopened.TriageActor != orchestrator.RiskAcceptanceExpiryActor || reopened.RiskAcceptedUntil != nil {
		t.Fatalf("expired acceptance = %+v (%v)", reopened, err)
	}
	if findings, accepted, _ := shadow(); findings != 5 || accepted != 0 {
		t.Fatalf("shadow posture after expiry: findings=%d accepted=%d", findings, accepted)
	}
}
