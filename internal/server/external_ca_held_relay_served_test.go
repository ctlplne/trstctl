// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"encoding/pem"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/orchestrator"
)

// TestServedRelayApprovalResumesTheHeldIssuanceN1L1 is N1-L1's "after
// approval": an issuance the CA held for a manager is resumed on its own once
// the issuer's relay approves its request behind trstctl's approval. Recording
// the relay's decision queues the resume in the same transaction, the
// resume reads the request back by its id, and the issuance's caller gets the
// certificate by replaying its request. A decision on a request no issuance
// is held on queues nothing.
func TestServedRelayApprovalResumesTheHeldIssuanceN1L1(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the certutil stand-in is a POSIX shell script")
	}
	standIn, certsrv := newADCSCertsrvStandIn(t)
	standIn.mu.Lock()
	standIn.hold = true
	standIn.seq = 4200 // request ids of its own; served tests share a tenant
	standIn.mu.Unlock()
	h := newRoleHarnessWithDeps(t, []string{mtls.AgentRoleNetwork}, []string{relay.KindADCSDecide}, func(d *Deps) {
		d.ExternalCAs = adcsRevocationConfig(t, certsrv.URL, "role-agent")
		d.RequiredApprovals = 1
	})
	startServedOutboxPump(t, h.srv)
	ctx := t.Context()
	previous := relay.CertutilPath
	t.Cleanup(func() { relay.CertutilPath = previous })
	relay.CertutilPath = writeCertutilDecideStandIn(t)
	requester := seedScopedTokenSubject(t, h.store, h.tenant, "held-requester", "certs:issue", "certs:read")
	reviewer := seedScopedTokenSubject(t, h.store, h.tenant, "held-reviewer", "certs:issue")
	call := func(token, method, path, key string, body any, want int) []byte {
		t.Helper()
		status, raw := secretsReqKey(t, h.servedHarness, method, path, token, key, body)
		if status != want {
			t.Fatalf("%s %s = %d, want %d: %s", method, path, status, want, raw)
		}
		return raw
	}
	heldList := func() []servedHeldIssue {
		t.Helper()
		var list struct {
			Items []servedHeldIssue `json:"items"`
		}
		if err := json.Unmarshal(call(requester, http.MethodGet, "/api/v1/external-cas/corp-adcs-web/held-issues", "", nil, http.StatusOK), &list); err != nil {
			t.Fatal(err)
		}
		var mine []servedHeldIssue
		for _, item := range list.Items {
			if item.CARequestID > 4200 && item.CARequestID < 4300 {
				mine = append(mine, item)
			}
		}
		return mine
	}
	countResumes := func() int {
		t.Helper()
		var n int
		if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT count(*) FROM outbox WHERE tenant_id = $1 AND destination = $2`,
				h.tenant, orchestrator.DestinationExternalCAResumeHeld).Scan(&n)
		}); err != nil {
			t.Fatal(err)
		}
		return n
	}
	waitHeld := func(want func([]servedHeldIssue) bool) []servedHeldIssue {
		t.Helper()
		deadline := time.Now().Add(30 * time.Second)
		for {
			items := heldList()
			if want(items) || time.Now().After(deadline) {
				return items
			}
			time.Sleep(50 * time.Millisecond)
		}
	}

	// The CA holds the issuance's request (request 4201).
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Destroy)
	csr, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: "relay-held.served.test", DNSNames: []string{"relay-held.served.test"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	issueBody := map[string]any{"csr_pem": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr})),
		"dns_names": []string{"relay-held.served.test"}, "ttl_seconds": 86400}
	if status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/external-cas/corp-adcs-web/issue", requester, "n1l1-relay-issue", issueBody); status == http.StatusCreated {
		t.Fatalf("an issuance the CA holds completed: %s", body)
	}
	if items := waitHeld(func(items []servedHeldIssue) bool { return len(items) == 1 }); len(items) != 1 || items[0].CARequestID != 4201 || items[0].Status != "held" {
		t.Fatalf("held issuances = %+v", items)
	}
	// The CA database knows request 4201 as pending; the relay approves it there,
	// and Web Enrollment then answers it issued (one CA, two stand-in halves).
	if err := os.WriteFile(filepath.Join(filepath.Dir(relay.CertutilPath), "4201"), []byte("pending"), 0o600); err != nil {
		t.Fatal(err)
	}
	standIn.approveHeld(t, 4201)

	type approval struct {
		ID     string `json:"approval_request_id"`
		Digest string `json:"approval_intent_digest"`
	}
	decide := func(requestID string) {
		t.Helper()
		var a approval
		if err := json.Unmarshal(call(requester, http.MethodPost, "/api/v1/external-cas/corp-adcs-web/adcs-requests/"+requestID+"/approval-requests",
			"n1l1-ask-"+requestID, map[string]any{"decision": "approve", "reason": "CHG-" + requestID}, http.StatusCreated), &a); err != nil {
			t.Fatal(err)
		}
		call(reviewer, http.MethodPost, "/api/v1/approval-requests/"+a.ID+"/approvals", "n1l1-review-"+requestID,
			map[string]any{"intent_digest": a.Digest, "reason": "checked"}, http.StatusOK)
		call(requester, http.MethodPost, "/api/v1/external-cas/corp-adcs-web/adcs-requests/"+requestID+"/decisions", "n1l1-exec-"+requestID,
			map[string]any{"approval_request_id": a.ID, "approval_intent_digest": a.Digest}, http.StatusCreated)
		channel := &sshCollectionServedChannel{t: t, h: h}
		if count, err := relay.RunOnce(ctx, channel, http.DefaultClient, 1, 120); err != nil || count != 1 {
			t.Fatalf("production relay = %d %v reports %+v", count, err, channel.reports)
		}
	}
	resumesBefore := countResumes()
	decide("4201")
	items := waitHeld(func(items []servedHeldIssue) bool { return len(items) == 1 && items[0].Status == "issued" })
	if len(items) != 1 || items[0].Status != "issued" || items[0].Serial == "" {
		t.Fatalf("after the relay's approval the held issuance = %+v; want issued", items)
	}
	// The issuance's caller replays its request and gets the certificate.
	status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/external-cas/corp-adcs-web/issue", requester, "n1l1-relay-issue", issueBody)
	var replayed struct {
		Serial string `json:"serial"`
	}
	if status != http.StatusCreated || json.Unmarshal(body, &replayed) != nil || replayed.Serial != items[0].Serial {
		t.Fatalf("the issuance's replay = %d %s; want serial %s", status, body, items[0].Serial)
	}

	// Approving a request no issuance is held on queues no resume.
	decide("77")
	if resumes := countResumes() - resumesBefore; resumes != 1 {
		t.Fatalf("%d resumes queued for one held issuance", resumes)
	}
}
