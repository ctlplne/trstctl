// SPDX-License-Identifier: MPL-2.0

package server

import (
	"bytes"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
	trstcrypto "trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/issuancerequest"
	"trstctl.com/trstctl/internal/store"
)

// I3 through the running binary.
//
// The lifecycle rules are unit-tested as pure functions, which proves the rules
// and proves nothing about whether a request can reach them. This drives the
// whole thing over HTTP against the assembled server.

type servedRequest struct {
	ID             string `json:"id"`
	IdentityID     string `json:"identity_id"`
	Status         string `json:"status"`
	Requester      string `json:"requester"`
	DecidedBy      string `json:"decided_by"`
	DecisionReason string `json:"decision_reason"`
	IssuedBy       string `json:"issued_by"`
	IssuedAt       string `json:"issued_at"`
	ExpiresAt      string `json:"expires_at"`
}

func openRequest(t *testing.T, h *servedHarness, tok, key, subject string) servedRequest {
	t.Helper()
	ownerAdmin := seedScopedTokenSubject(t, h.store, h.tenant, "owner-admin:"+key, string(authz.OwnersWrite))
	ownerID := servedCreateID(t, h, ownerAdmin, key+"-owner", "/api/v1/owners", map[string]any{
		"kind": "workload", "name": key + "-owner",
	})
	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/issuance-requests", tok, key, map[string]any{
		"subject":       subject,
		"owner_id":      ownerID,
		"justification": "renewing the payments gateway leaf",
	})
	if status != http.StatusCreated {
		t.Fatalf("open request: status %d body %s", status, body)
	}
	var out servedRequest
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// A requester must not be able to approve their own request over HTTP. The unit
// test proves CanDecide refuses; this proves the served path actually calls it.
func TestServedRequesterCannotApproveTheirOwnRequest(t *testing.T) {
	h := newServedHarness(t, config.Protocols{})
	tok := seedScopedTokenSubject(t, h.store, h.tenant, "alice@example.com", "certs:request", "certs:issue")
	req := openRequest(t, h, tok, "i3-self-approve", "payments.example.com")
	if req.Requester != "alice@example.com" {
		t.Fatalf("requester = %q, want the authenticated principal", req.Requester)
	}

	status, body := secretsReqKey(t, h, http.MethodPost,
		"/api/v1/issuance-requests/"+req.ID+"/approve", tok, "i3-self-approve-2", nil)
	if status == http.StatusOK {
		t.Fatalf("alice approved her own request (status %d, body %s).\n\n"+
			"That is a bypass of dual control that leaves an approval record looking legitimate: "+
			"the row says somebody approved it, and that somebody is the person who asked.",
			status, body)
	}
}

// A denial must carry a reason, and must be final.
func TestServedDenialCarriesAReasonAndIsFinal(t *testing.T) {
	h := newServedHarness(t, config.Protocols{})
	alice := seedScopedTokenSubject(t, h.store, h.tenant, "alice@example.com", "certs:request")
	bob := seedScopedTokenSubject(t, h.store, h.tenant, "bob@example.com", "certs:request", "certs:issue")
	req := openRequest(t, h, alice, "i3-deny", "api.example.com")

	// No reason: refused.
	status, _ := secretsReqKey(t, h, http.MethodPost,
		"/api/v1/issuance-requests/"+req.ID+"/deny", bob, "i3-deny-noreason", map[string]any{})
	if status == http.StatusOK {
		t.Fatal("a denial with no reason was accepted. The requester learns only that somebody " +
			"said no, and simply asks again")
	}

	status, body := secretsReqKey(t, h, http.MethodPost,
		"/api/v1/issuance-requests/"+req.ID+"/deny", bob, "i3-deny-ok", map[string]any{
			"reason": "this hostname is already covered by the wildcard",
		})
	if status != http.StatusOK {
		t.Fatalf("deny: status %d body %s", status, body)
	}
	var denied servedRequest
	if err := json.Unmarshal(body, &denied); err != nil {
		t.Fatal(err)
	}
	if denied.Status != issuancerequest.StateDenied || denied.DecidedBy != "bob@example.com" {
		t.Fatalf("denied request = %+v", denied)
	}

	// A second reviewer must not be able to overturn it.
	status, body = secretsReqKey(t, h, http.MethodPost,
		"/api/v1/issuance-requests/"+req.ID+"/approve", bob, "i3-deny-overturn", nil)
	if status == http.StatusOK {
		t.Fatalf("a denied request was approved (body %s).\n\n"+
			"A closed request that can be re-decided lets a second reviewer overturn the first "+
			"without either of them knowing, and the audit trail shows both with nothing saying "+
			"which one governs.", body)
	}
}

// Only the requester may withdraw. Somebody else closing it is a denial and has
// to be recorded as one, with a reason.
func TestServedOnlyTheRequesterCanCancel(t *testing.T) {
	h := newServedHarness(t, config.Protocols{})
	alice := seedScopedTokenSubject(t, h.store, h.tenant, "alice@example.com", "certs:request")
	bob := seedScopedTokenSubject(t, h.store, h.tenant, "bob@example.com", "certs:request", "certs:issue")
	req := openRequest(t, h, alice, "i3-cancel", "cancel.example.com")

	status, _ := secretsReqKey(t, h, http.MethodPost,
		"/api/v1/issuance-requests/"+req.ID+"/cancel", bob, "i3-cancel-bob", nil)
	if status == http.StatusOK {
		t.Fatal("bob withdrew alice's request. Someone else closing a request is a DENIAL and " +
			"must be recorded as one, with a reason the requester can act on")
	}
	status, body := secretsReqKey(t, h, http.MethodPost,
		"/api/v1/issuance-requests/"+req.ID+"/cancel", alice, "i3-cancel-alice", nil)
	if status != http.StatusOK {
		t.Fatalf("alice could not withdraw her own request: %d %s", status, body)
	}
}

// The expiry sweep must close overdue requests with NO decider.
func TestServedExpirySweepClosesWithoutAttributingADecision(t *testing.T) {
	h := newServedHarness(t, config.Protocols{})
	alice := seedScopedTokenSubject(t, h.store, h.tenant, "alice@example.com", "certs:request")
	req := openRequest(t, h, alice, "i3-expiry", "expiring.example.com")

	// Backdate it past due. The sweep's own clock decides; this is the only way
	// to test it without waiting seven days.
	if _, err := h.store.SystemPool().Exec(t.Context(),
		`UPDATE issuance_requests SET expires_at = $2 WHERE id = $1`,
		req.ID, time.Now().UTC().Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	n, err := h.srv.RunIssuanceRequestExpiryOnce(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("expired %d requests, want 1. Without the sweep a request nobody decided sits in "+
			"the queue forever and the queue's size stops meaning anything", n)
	}
	stored, err := h.store.GetIssuanceRequest(t.Context(), h.tenant, req.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Status != issuancerequest.StateExpired {
		t.Fatalf("status = %q, want expired", stored.Status)
	}
	if stored.DecidedBy != "" {
		t.Fatalf("expiry was attributed to %q. Nobody decided it — time ran out — and stamping a "+
			"person on it puts a decision in the audit trail that no human ever made", stored.DecidedBy)
	}
}

// The list surface must serve closed requests too: an auditor asking what was
// DENIED needs them as much as the queue needs the pending ones.
func TestServedListIncludesClosedRequestsAndCountsOpenSeparately(t *testing.T) {
	h := newServedHarness(t, config.Protocols{})
	alice := seedScopedTokenSubject(t, h.store, h.tenant, "alice@example.com", "certs:request", "certs:read")
	bob := seedScopedTokenSubject(t, h.store, h.tenant, "bob@example.com", "certs:request", "certs:issue")
	open := openRequest(t, h, alice, "i3-list-open", "open.example.com")
	closed := openRequest(t, h, alice, "i3-list-closed", "closed.example.com")
	_ = open
	if status, body := secretsReqKey(t, h, http.MethodPost,
		"/api/v1/issuance-requests/"+closed.ID+"/deny", bob, "i3-list-deny", map[string]any{
			"reason": "duplicate",
		}); status != http.StatusOK {
		t.Fatalf("deny: %d %s", status, body)
	}

	status, body := secretsReq(t, h, http.MethodGet, "/api/v1/issuance-requests", alice, nil)
	if status != http.StatusOK {
		t.Fatalf("list: %d %s", status, body)
	}
	var list struct {
		Items []servedRequest `json:"items"`
		Open  int             `json:"open"`
	}
	if err := json.Unmarshal(body, &list); err != nil {
		t.Fatal(err)
	}
	if len(list.Items) != 2 {
		t.Fatalf("list returned %d items, want both. A list that hides closed requests cannot "+
			"answer what was denied", len(list.Items))
	}
	if list.Open != 1 {
		t.Fatalf("open = %d, want 1. One total cannot say whether a queue needs attention or is "+
			"merely long with history", list.Open)
	}
}

// An approved first-class request must be able to reach a real certificate.
// Approval is deliberately not issuance, but a lifecycle with no served bridge
// from approved to signer-backed identity leaves honest requests wedged forever.
// This drives the complete public path and proves the bridge reuses the normal
// identity mutation gate, requester-held CSR, outbox, signer, and inventory.
func TestServedApprovedIssuanceRequestCanBePreparedIssuedAndCompleted(t *testing.T) {
	h := newServedHarness(t, config.Protocols{})
	admin := seedScopedTokenSubject(t, h.store, h.tenant, "request-admin@example.test",
		string(authz.OwnersWrite), string(authz.ProfilesWrite))
	requester := seedScopedTokenSubject(t, h.store, h.tenant, "requester@example.test",
		string(authz.CertsRequest), string(authz.CertsRead))
	reviewer := seedScopedTokenSubject(t, h.store, h.tenant, "reviewer@example.test",
		string(authz.CertsIssue))
	issuer := seedScopedTokenSubject(t, h.store, h.tenant, "issuer@example.test",
		string(authz.IdentitiesWrite), string(authz.IdentitiesRead),
		string(authz.CertsIssue), string(authz.CertsRead))

	ownerID := servedCreateID(t, h, admin, "i3-fulfill-owner", "/api/v1/owners", map[string]any{
		"kind": "workload", "name": "payments-platform",
	})
	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/profiles", admin,
		"i3-fulfill-profile", map[string]any{
			"name": "service-mtls-30d",
			"spec": map[string]any{
				"subject":         map[string]any{"common_name": "qa-design-partner-mtls"},
				"max_ttl_seconds": 2_592_000,
			},
		})
	if status != http.StatusCreated {
		t.Fatalf("create request profile: status %d body %s", status, body)
	}

	hostKey, err := trstcrypto.GenerateHostSubjectKey("qa-design-partner-mtls", []string{"qa-design-partner-mtls"})
	if err != nil {
		t.Fatalf("generate requester-held CSR: %v", err)
	}
	defer hostKey.Destroy()
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: hostKey.CSRDER})

	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/issuance-requests", requester,
		"i3-fulfill-open", map[string]any{
			"subject": "qa-design-partner-mtls", "owner_id": ownerID,
			"profile": "service-mtls-30d:1", "csr_pem": string(csrPEM),
			"justification": "prove the design-partner mTLS request can really be fulfilled",
			"origin":        "console",
		})
	if status != http.StatusCreated {
		t.Fatalf("open request: status %d body %s", status, body)
	}
	var opened servedRequest
	if err := json.Unmarshal(body, &opened); err != nil || opened.ID == "" {
		t.Fatalf("decode opened request: %+v err=%v body=%s", opened, err, body)
	}

	status, body = secretsReqKey(t, h, http.MethodPost,
		"/api/v1/issuance-requests/"+opened.ID+"/approve", reviewer, "i3-fulfill-approve", nil)
	if status != http.StatusOK {
		t.Fatalf("approve request: status %d body %s", status, body)
	}

	status, body = secretsReqKey(t, h, http.MethodPost,
		"/api/v1/issuance-requests/"+opened.ID+"/prepare", issuer, "issuance-request-prepare:"+opened.ID, nil)
	if status != http.StatusOK {
		t.Fatalf("prepare approved request: status %d body %s", status, body)
	}
	var prepared struct {
		Request  servedRequest `json:"request"`
		Identity struct {
			ID     string `json:"id"`
			Status string `json:"status"`
		} `json:"identity"`
		CSRPEM string `json:"csr_pem"`
	}
	if err := json.Unmarshal(body, &prepared); err != nil {
		t.Fatalf("decode prepared request: %v body=%s", err, body)
	}
	preparedCSR, _ := pem.Decode([]byte(prepared.CSRPEM))
	originalCSR, _ := pem.Decode(csrPEM)
	csrPreserved := preparedCSR != nil && originalCSR != nil && bytes.Equal(preparedCSR.Bytes, originalCSR.Bytes)
	if prepared.Request.Status != issuancerequest.StateApproved || prepared.Request.IdentityID == "" ||
		prepared.Request.IdentityID != prepared.Identity.ID || prepared.Identity.Status != "requested" ||
		!csrPreserved {
		t.Fatalf("prepared response = %+v; CSR DER preserved=%v", prepared, csrPreserved)
	}

	// Completion is evidence-based: an approved row and a prepared identity are
	// not enough. No matching signer result means no "issued" status.
	completionKey := "issuance-request-complete:" + opened.ID
	status, body = secretsReqKey(t, h, http.MethodPost,
		"/api/v1/issuance-requests/"+opened.ID+"/complete", issuer, completionKey, nil)
	if status != http.StatusConflict {
		t.Fatalf("complete before mint: status %d body %s, want 409", status, body)
	}

	issueKey := "issuance-request-issue:" + opened.ID
	status, body = secretsReqKey(t, h, http.MethodPost,
		"/api/v1/identities/"+prepared.Identity.ID+"/transitions", issuer, issueKey, map[string]any{
			"to": "issued", "reason": "fulfill approved issuance request " + opened.ID,
			"subject_csr_pem": prepared.CSRPEM,
		})
	if status != http.StatusOK {
		t.Fatalf("issue prepared identity: status %d body %s", status, body)
	}
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatalf("drain request issuance outbox: %v", err)
	}
	preCompletionCerts, preCompletionErr := h.store.ListActiveIssuedCertificatesForIdentity(
		t.Context(), h.tenant, ownerID, "qa-design-partner-mtls")
	if preCompletionErr != nil {
		t.Fatalf("read pre-completion certificate evidence: %v", preCompletionErr)
	}
	preCompletionKeys := make([]string, 0, len(preCompletionCerts))
	for _, certificate := range preCompletionCerts {
		preCompletionKeys = append(preCompletionKeys, certificate.IssuanceIdempotencyKey)
	}
	// A rollover after the signer result is a new rule for the next mint. It
	// cannot rewrite history or strand this already-minted v1 request at
	// "approved". Completion verifies the exact retained v1 revision instead.
	activeProfile, err := h.store.GetActiveProfile(t.Context(), h.tenant, "service-mtls-30d")
	if err != nil {
		t.Fatalf("read active profile before rollover: %v", err)
	}
	rolledProfile, err := h.store.CreateProfileVersion(t.Context(), store.ProfileRecord{
		TenantID: h.tenant, Name: activeProfile.Name, Spec: activeProfile.Spec, CreatedBy: "profile-rollover@example.test",
	})
	if err != nil || rolledProfile.Version != activeProfile.Version+1 {
		t.Fatalf("roll profile after mint: version=%d err=%v", rolledProfile.Version, err)
	}

	status, body = secretsReqKey(t, h, http.MethodPost,
		"/api/v1/issuance-requests/"+opened.ID+"/complete", issuer,
		completionKey, nil)
	if status != http.StatusOK {
		t.Fatalf("complete issued request: status %d body %s; certificate keys=%v", status, body, preCompletionKeys)
	}
	var completed servedRequest
	if err := json.Unmarshal(body, &completed); err != nil {
		t.Fatalf("decode completed request: %v body=%s", err, body)
	}
	if completed.Status != issuancerequest.StateIssued || completed.IdentityID != prepared.Identity.ID ||
		completed.DecidedBy != "reviewer@example.test" || completed.IssuedBy != "issuer@example.test" || completed.IssuedAt == "" {
		t.Fatalf("completed request = %+v", completed)
	}

	certs, err := h.store.ListActiveIssuedCertificatesForIdentity(t.Context(), h.tenant, ownerID, "qa-design-partner-mtls")
	if err != nil || len(certs) != 1 {
		t.Fatalf("matching issued certificates = %d err=%v", len(certs), err)
	}
	if certs[0].IssuanceIdempotencyKey != "issue:transition:"+issueKey ||
		(len(certs[0].CertificateDER) == 0 && len(certs[0].CertificatePEM) == 0) {
		t.Fatalf("issued certificate is not bound to the approved request: key=%q der=%d pem=%d",
			certs[0].IssuanceIdempotencyKey, len(certs[0].CertificateDER), len(certs[0].CertificatePEM))
	}

	for _, eventType := range []string{"issuance.request.prepared", "identity.issued", "certificate.recorded", "issuance.request.issued"} {
		if !h.hasEvent(t, eventType) {
			t.Fatalf("missing %s event for the fulfilled first-class request", eventType)
		}
	}
}
