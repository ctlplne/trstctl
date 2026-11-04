// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/crypto/mtls"
)

// writeCertutilDecideStandIn is a CA database stand-in for decisions: request
// 77 and 78 are pending, 79 a manager already denied. -resubmit issues a
// pending request (serial 1a0000 followed by its id), -deny denies it; state
// lives in one file per request.
func writeCertutilDecideStandIn(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for id, state := range map[string]string{"77": "pending", "78": "pending", "79": "denied"} {
		if err := os.WriteFile(filepath.Join(dir, id), []byte(state), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	script := filepath.Join(dir, "certutil")
	body := `#!/bin/sh
S='` + dir + `'
[ "$1" = -config ] && [ "$2" = '` + adcsRevocationCA + `' ] || exit 2
case "$3" in
-resubmit) [ "$(cat "$S/$4")" = pending ] || exit 4; printf issued > "$S/$4" ;;
-deny) [ "$(cat "$S/$4")" = pending ] || exit 4; printf denied > "$S/$4" ;;
-view) id="${5#RequestID=}"; state=$(cat "$S/$id" 2>/dev/null); serial=''
  case "$state" in
  pending) d='9 -- Pending' ;;
  issued) d='20 -- Issued'; serial="1a0000$id" ;;
  denied) d='31 -- Denied' ;;
  *) printf '"Request ID","Serial Number","Request Disposition"\n'; exit 0 ;;
  esac
  printf '"Request ID","Serial Number","Request Disposition"\n"%s","%s","%s"\n' "$id" "$serial" "$d" ;;
*) exit 2 ;;
esac
`
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil { // #nosec G306 -- a test-owned executable stand-in (CWE-276).
		t.Fatal(err)
	}
	return script
}

// N1: AD CS approve and deny through the agent on the CA's network, behind
// approval. A request a template holds for a CA manager is approved or denied
// at the CA by the issuer's relay only after another reviewer approves the
// exact decision; the relay acts only while the CA holds the request as
// pending and the decision is recorded from its readback.
func TestServedADCSDecisionsThroughTheRelayBehindApprovalN1(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the certutil stand-in is a POSIX shell script")
	}
	_, certsrv := newADCSCertsrvStandIn(t)
	h := newRoleHarnessWithDeps(t, []string{mtls.AgentRoleNetwork}, []string{relay.KindADCSDecide}, func(d *Deps) {
		d.ExternalCAs = adcsRevocationConfig(t, certsrv.URL, "role-agent")
		d.RequiredApprovals = 1
	})
	ctx := t.Context()
	previous := relay.CertutilPath
	t.Cleanup(func() { relay.CertutilPath = previous })
	relay.CertutilPath = writeCertutilDecideStandIn(t)
	requester := seedScopedTokenSubject(t, h.store, h.tenant, "adcs-requester", "certs:issue", "certs:read")
	reviewer := seedScopedTokenSubject(t, h.store, h.tenant, "adcs-reviewer", "certs:issue")
	call := func(token, method, path, key string, body any, want int) []byte {
		t.Helper()
		status, raw := secretsReqKey(t, h.servedHarness, method, path, token, key, body)
		if status != want {
			t.Fatalf("%s %s = %d, want %d: %s", method, path, status, want, raw)
		}
		return raw
	}
	base := "/api/v1/external-cas/corp-adcs-web/adcs-requests/"
	type approval struct {
		ID     string `json:"approval_request_id"`
		Digest string `json:"approval_intent_digest"`
		Status string `json:"status"`
	}
	ask := func(requestID, decision string) approval {
		t.Helper()
		var a approval
		if err := json.Unmarshal(call(requester, http.MethodPost, base+requestID+"/approval-requests", "n1-ask-"+requestID+"-"+decision,
			map[string]any{"decision": decision, "reason": "change ticket CHG-" + requestID}, http.StatusCreated), &a); err != nil {
			t.Fatal(err)
		}
		if a.ID == "" || a.Digest == "" {
			t.Fatalf("approval request = %+v", a)
		}
		return a
	}
	execute := func(requestID string, a approval, key string, want int) []byte {
		t.Helper()
		return call(requester, http.MethodPost, base+requestID+"/decisions", key,
			map[string]any{"approval_request_id": a.ID, "approval_intent_digest": a.Digest}, want)
	}
	runRelay := func() {
		t.Helper()
		channel := &sshCollectionServedChannel{t: t, h: h}
		if count, err := relay.RunOnce(ctx, channel, http.DefaultClient, 1, 120); err != nil || count != 1 {
			t.Fatalf("production relay = %d %v reports %+v", count, err, channel.reports)
		}
	}
	type decisionView struct {
		ID          string `json:"id"`
		RequestID   int    `json:"request_id"`
		Decision    string `json:"decision"`
		Status      string `json:"status"`
		Disposition string `json:"disposition"`
		Serial      string `json:"serial"`
		Failure     string `json:"failure"`
		RequestedBy string `json:"requested_by"`
	}
	decisions := func() map[int]decisionView {
		t.Helper()
		var list struct {
			Items []decisionView `json:"items"`
		}
		if err := json.Unmarshal(call(requester, http.MethodGet, "/api/v1/external-cas/corp-adcs-web/adcs-decisions", "", nil, http.StatusOK), &list); err != nil {
			t.Fatal(err)
		}
		out := map[int]decisionView{}
		for _, d := range list.Items {
			out[d.RequestID] = d
		}
		return out
	}

	// Approve request 77: nothing reaches the CA before another reviewer
	// approves; the requester cannot approve their own decision.
	a77 := ask("77", "approve")
	execute("77", a77, "n1-exec-77-early", http.StatusConflict)
	if status, _ := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/approval-requests/"+a77.ID+"/approvals", requester,
		"n1-self-approve", map[string]any{"intent_digest": a77.Digest, "reason": "my own"}); status < 400 {
		t.Fatalf("the requester approved their own AD CS decision: %d", status)
	}
	call(reviewer, http.MethodPost, "/api/v1/approval-requests/"+a77.ID+"/approvals", "n1-review-77",
		map[string]any{"intent_digest": a77.Digest, "reason": "checked the request"}, http.StatusOK)
	var queued decisionView
	if err := json.Unmarshal(execute("77", a77, "n1-exec-77", http.StatusCreated), &queued); err != nil {
		t.Fatal(err)
	}
	if queued.Status != "queued" || queued.Decision != "approve" || queued.RequestedBy != "adcs-requester" {
		t.Fatalf("queued decision = %+v", queued)
	}
	// The approval is spent on exactly one relay job.
	execute("77", a77, "n1-exec-77-again", http.StatusCreated)
	if n := adcsDecisionJobs(t, h); n != 1 {
		t.Fatalf("%d decision jobs queued for one approval, want 1", n)
	}
	runRelay()
	if d := decisions()[77]; d.Status != "decided" || d.Disposition != "issued" || d.Serial != "1a000077" {
		t.Fatalf("approved decision = %+v", d)
	}

	// Deny request 78.
	a78 := ask("78", "deny")
	call(reviewer, http.MethodPost, "/api/v1/approval-requests/"+a78.ID+"/approvals", "n1-review-78",
		map[string]any{"intent_digest": a78.Digest, "reason": "not our template"}, http.StatusOK)
	execute("78", a78, "n1-exec-78", http.StatusCreated)
	runRelay()
	if d := decisions()[78]; d.Status != "decided" || d.Disposition != "denied" || d.Serial != "" {
		t.Fatalf("denied decision = %+v", d)
	}

	// Request 79 was already denied at the CA: the relay changes nothing, so
	// an approval can never re-issue a request a manager refused.
	a79 := ask("79", "approve")
	call(reviewer, http.MethodPost, "/api/v1/approval-requests/"+a79.ID+"/approvals", "n1-review-79",
		map[string]any{"intent_digest": a79.Digest, "reason": "retry"}, http.StatusOK)
	execute("79", a79, "n1-exec-79", http.StatusCreated)
	channel := &sshCollectionServedChannel{t: t, h: h}
	if _, err := relay.RunOnce(ctx, channel, http.DefaultClient, 1, 120); err != nil {
		t.Fatal(err)
	}
	if d := decisions()[79]; d.Status != "failed" || !strings.Contains(d.Failure, "not hold request 79 as pending (denied)") {
		t.Fatalf("decision on a denied request = %+v", d)
	}
	if state, err := os.ReadFile(filepath.Join(filepath.Dir(relay.CertutilPath), "79")); err != nil || string(state) != "denied" {
		t.Fatalf("request 79 at the CA = %q %v", state, err)
	}

	// An issuer with no AD CS relay route takes no decision.
	call(requester, http.MethodPost, "/api/v1/external-cas/no-such-issuer/adcs-requests/77/approval-requests", "n1-no-route",
		map[string]any{"decision": "approve", "reason": "x"}, http.StatusConflict)
}

// adcsDecisionJobs counts the relay decision jobs queued in the harness's tenant.
func adcsDecisionJobs(t *testing.T, h *roleHarness) int {
	t.Helper()
	var n int
	if err := h.store.WithTenant(t.Context(), h.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(t.Context(), `SELECT count(*) FROM outbox WHERE tenant_id = $1 AND destination = $2`,
			h.tenant, relay.KindADCSDecide).Scan(&n)
	}); err != nil {
		t.Fatal(err)
	}
	return n
}
