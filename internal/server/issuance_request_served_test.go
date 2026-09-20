// SPDX-License-Identifier: BUSL-1.1

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

// A request preview is a question, not a mutation. It must run the same
// tenant-scoped owner/profile/CSR admission rule as the later POST while
// proving that asking the question created no event, projection, idempotency
// receipt, outbox intent, identity, or certificate.
func TestServedIssuanceRequestPreviewIsEffectFreeAndMatchesAdmission(t *testing.T) {
	h := newServedHarness(t, config.Protocols{})
	admin := seedScopedTokenSubject(t, h.store, h.tenant, "preview-admin@example.test",
		string(authz.OwnersWrite), string(authz.ProfilesWrite))
	requester := seedScopedTokenSubject(t, h.store, h.tenant, "preview-requester@example.test",
		string(authz.CertsRequest), string(authz.CertsRead))
	ownerID := servedCreateID(t, h, admin, "preview-owner", "/api/v1/owners", map[string]any{
		"kind": "team", "name": "Payments platform",
	})
	if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/profiles", admin,
		"preview-profile", map[string]any{
			"name": "service-mtls-30d",
			"spec": map[string]any{
				"subject":         map[string]any{"common_name": "preview.example.test"},
				"max_ttl_seconds": 2_592_000,
			},
		}); status != http.StatusCreated {
		t.Fatalf("create preview profile: status %d body %s", status, body)
	}

	input := map[string]any{
		"subject": "payments-api", "owner_id": ownerID,
		"profile": "service-mtls-30d", "justification": "staging mTLS", "origin": "console",
	}
	eventHeadBefore, err := h.log.LastSequence(t.Context())
	if err != nil {
		t.Fatalf("event head before preview: %v", err)
	}
	var requestsBefore, identitiesBefore, certificatesBefore, outboxBefore, idempotencyBefore int
	if err := h.store.SystemPool().QueryRow(t.Context(), `
		SELECT
		  (SELECT count(*) FROM issuance_requests WHERE tenant_id = $1),
		  (SELECT count(*) FROM identities WHERE tenant_id = $1),
		  (SELECT count(*) FROM certificates WHERE tenant_id = $1),
		  (SELECT count(*) FROM outbox WHERE tenant_id = $1),
		  (SELECT count(*) FROM idempotency_keys WHERE tenant_id = $1)`, h.tenant).
		Scan(&requestsBefore, &identitiesBefore, &certificatesBefore, &outboxBefore, &idempotencyBefore); err != nil {
		t.Fatalf("count state before preview: %v", err)
	}

	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/issuance-requests/preview", requester, input)
	if status != http.StatusOK {
		t.Fatalf("preview request: status %d body %s", status, body)
	}
	var preview struct {
		Ready                  bool     `json:"ready"`
		Subject                string   `json:"subject"`
		OwnerID                string   `json:"owner_id"`
		OwnerName              string   `json:"owner_name"`
		Profile                string   `json:"profile"`
		ProfileName            string   `json:"profile_name"`
		ProfileVersion         int      `json:"profile_version"`
		Requester              string   `json:"requester"`
		KeyOrigin              string   `json:"key_origin"`
		ApprovalPermission     string   `json:"approval_permission"`
		PreviewWrites          []string `json:"preview_writes"`
		PreviewExternalEffects []string `json:"preview_external_effects"`
		SubmissionEffects      []string `json:"submission_effects"`
		Blockers               []string `json:"blockers"`
	}
	if err := json.Unmarshal(body, &preview); err != nil {
		t.Fatalf("decode preview: %v body=%s", err, body)
	}
	if !preview.Ready || preview.Subject != "payments-api" || preview.OwnerID != ownerID ||
		preview.OwnerName != "Payments platform" || preview.Profile != "service-mtls-30d:1" ||
		preview.ProfileName != "service-mtls-30d" || preview.ProfileVersion != 1 ||
		preview.Requester != "preview-requester@example.test" ||
		preview.KeyOrigin != "deprecated_control_plane_generation" ||
		preview.ApprovalPermission != string(authz.CertsIssue) || len(preview.Blockers) != 0 ||
		len(preview.PreviewWrites) != 0 || len(preview.PreviewExternalEffects) != 0 ||
		len(preview.SubmissionEffects) < 3 {
		t.Fatalf("preview = %+v", preview)
	}

	eventHeadAfter, err := h.log.LastSequence(t.Context())
	if err != nil {
		t.Fatalf("event head after preview: %v", err)
	}
	var requestsAfter, identitiesAfter, certificatesAfter, outboxAfter, idempotencyAfter int
	if err := h.store.SystemPool().QueryRow(t.Context(), `
		SELECT
		  (SELECT count(*) FROM issuance_requests WHERE tenant_id = $1),
		  (SELECT count(*) FROM identities WHERE tenant_id = $1),
		  (SELECT count(*) FROM certificates WHERE tenant_id = $1),
		  (SELECT count(*) FROM outbox WHERE tenant_id = $1),
		  (SELECT count(*) FROM idempotency_keys WHERE tenant_id = $1)`, h.tenant).
		Scan(&requestsAfter, &identitiesAfter, &certificatesAfter, &outboxAfter, &idempotencyAfter); err != nil {
		t.Fatalf("count state after preview: %v", err)
	}
	if eventHeadAfter != eventHeadBefore || requestsAfter != requestsBefore || identitiesAfter != identitiesBefore ||
		certificatesAfter != certificatesBefore || outboxAfter != outboxBefore || idempotencyAfter != idempotencyBefore {
		t.Fatalf("preview mutated state: event=%d->%d requests=%d->%d identities=%d->%d certificates=%d->%d outbox=%d->%d idempotency=%d->%d",
			eventHeadBefore, eventHeadAfter, requestsBefore, requestsAfter, identitiesBefore, identitiesAfter,
			certificatesBefore, certificatesAfter, outboxBefore, outboxAfter, idempotencyBefore, idempotencyAfter)
	}

	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/issuance-requests", requester,
		"preview-admission", input)
	if status != http.StatusCreated {
		t.Fatalf("create after green preview: status %d body %s", status, body)
	}
	var created struct {
		Subject   string `json:"subject"`
		OwnerID   string `json:"owner_id"`
		Profile   string `json:"profile"`
		Requester string `json:"requester"`
	}
	if err := json.Unmarshal(body, &created); err != nil {
		t.Fatalf("decode created request: %v body=%s", err, body)
	}
	if created.Subject != preview.Subject || created.OwnerID != preview.OwnerID ||
		created.Profile != preview.Profile || created.Requester != preview.Requester {
		t.Fatalf("admitted request = %+v, preview = %+v", created, preview)
	}
}

func TestServedIssuanceRequestPreviewNamesConfigurationBlockersWithoutTenantLeakage(t *testing.T) {
	h := newServedHarness(t, config.Protocols{})
	const otherTenant = "22222222-2222-2222-2222-222222222222"
	otherOwnerID := createAUD78Owner(t, h, otherTenant, "Other tenant")
	requester := seedScopedTokenSubject(t, h.store, h.tenant, "preview-requester@example.test",
		string(authz.CertsRequest))

	preview := func(ownerID, profile string) (int, []byte) {
		t.Helper()
		return secretsReq(t, h, http.MethodPost, "/api/v1/issuance-requests/preview", requester, map[string]any{
			"subject": "payments-api", "owner_id": ownerID, "profile": profile,
		})
	}
	missingOwner := "33333333-3333-4333-8333-333333333333"
	otherStatus, otherBody := preview(otherOwnerID, "missing-profile:1")
	missingStatus, missingBody := preview(missingOwner, "missing-profile:1")
	if otherStatus != http.StatusOK || missingStatus != http.StatusOK {
		t.Fatalf("blocked previews = other %d %s; missing %d %s", otherStatus, otherBody, missingStatus, missingBody)
	}
	var other, missing struct {
		Ready    bool     `json:"ready"`
		Blockers []string `json:"blockers"`
	}
	if err := json.Unmarshal(otherBody, &other); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(missingBody, &missing); err != nil {
		t.Fatal(err)
	}
	if other.Ready || missing.Ready || len(other.Blockers) != 2 || len(missing.Blockers) != 2 ||
		other.Blockers[0] != missing.Blockers[0] || other.Blockers[1] != missing.Blockers[1] {
		t.Fatalf("tenant-safe blockers differ: other=%+v missing=%+v", other, missing)
	}

	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/issuance-requests", requester,
		"blocked-preview-admission", map[string]any{
			"subject": "payments-api", "owner_id": otherOwnerID, "profile": "missing-profile:1",
		})
	if status != http.StatusUnprocessableEntity {
		t.Fatalf("blocked admission: status %d body %s", status, body)
	}
	if head, err := h.log.LastSequence(t.Context()); err != nil || head != 1 {
		// createAUD78Owner appended exactly one event for the other tenant. A
		// refused request must not append a second one in either tenant.
		t.Fatalf("blocked admission changed event head: head=%d err=%v", head, err)
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
		string(authz.CertsIssue), string(authz.CertsRead), string(authz.CertsWrite))

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

	// The request subject is a friendly work-item label. A requester-held CSR is
	// allowed to carry the real X.509 name, and completion must not confuse the
	// two different concepts when locating signer evidence.
	csrName := "qa-design-partner.demo.trstctl.local"
	hostKey, err := trstcrypto.GenerateHostSubjectKey(csrName, []string{csrName})
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
	certificateKey := "issue:transition:" + issueKey
	preCompletionCerts, preCompletionErr := h.store.ListCertificatesByIssuanceIdempotencyKey(
		t.Context(), h.tenant, certificateKey)
	if preCompletionErr != nil {
		t.Fatalf("read pre-completion certificate evidence: %v", preCompletionErr)
	}
	preCompletionKeys := make([]string, 0, len(preCompletionCerts))
	for _, certificate := range preCompletionCerts {
		preCompletionKeys = append(preCompletionKeys, certificate.IssuanceIdempotencyKey)
	}
	// Re-import through the normal served inventory path before completing the
	// approval. This must update observation provenance without stranding the
	// exact requester-held issuance at approved or altering its public output.
	if len(preCompletionCerts) != 1 || len(preCompletionCerts[0].CertificateDER) == 0 {
		t.Fatalf("expected one real pre-completion leaf: %+v", preCompletionCerts)
	}
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/certificates", issuer,
		"i3-fulfill-public-reimport", map[string]any{
			"pem":      string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: preCompletionCerts[0].CertificateDER})),
			"owner_id": ownerID,
		})
	if status != http.StatusCreated {
		t.Fatalf("approved leaf import: %d %s", status, body)
	}
	imported, err := h.store.GetCertificate(t.Context(), h.tenant, preCompletionCerts[0].ID)
	if err != nil || imported.Source != "import" || !bytes.Equal(imported.CertificatePEM, preCompletionCerts[0].CertificatePEM) {
		t.Fatalf("import changed public issuance or hid provenance: source=%q err=%v", imported.Source, err)
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

	certs, err := h.store.ListCertificatesByIssuanceIdempotencyKey(t.Context(), h.tenant, certificateKey)
	if err != nil || len(certs) != 1 {
		t.Fatalf("matching issued certificates = %d err=%v", len(certs), err)
	}
	if certs[0].IssuanceIdempotencyKey != certificateKey || certs[0].Subject == "CN=qa-design-partner-mtls" ||
		(len(certs[0].CertificateDER) == 0 && len(certs[0].CertificatePEM) == 0) {
		t.Fatalf("issued certificate is not bound to the approved request and real CSR name: key=%q subject=%q der=%d pem=%d",
			certs[0].IssuanceIdempotencyKey, certs[0].Subject, len(certs[0].CertificateDER), len(certs[0].CertificatePEM))
	}

	for _, eventType := range []string{"issuance.request.prepared", "identity.issued", "certificate.recorded", "issuance.request.issued"} {
		if !h.hasEvent(t, eventType) {
			t.Fatalf("missing %s event for the fulfilled first-class request", eventType)
		}
	}
}
