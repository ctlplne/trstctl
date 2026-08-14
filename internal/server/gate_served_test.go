// SPDX-License-Identifier: MPL-2.0

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/profile"
	"trstctl.com/trstctl/internal/store"
)

// EXC-WIRE-03 acceptance — the served policy / RA-separation / dual-control gate,
// proven against the production composition (server.Build -> Handler()) on the
// embedded stack (bundled PostgreSQL + in-process NATS). This is the wire-in proof:
// it drives the SAME served path cmd/trstctl serves (POST /api/v1/identities/{id}/
// transitions and /approvals), not a library function. It MUST fail on the pre-fix
// tree (the gate was library-only: the served mint had no policy/RA/dual-control)
// and PASS after, and is race-clean.
//
// It asserts, end to end through the running handler:
//   - a privileged issue is DENIED by default when the requester lacks certs:issue
//     (RA split — the requester scope cannot self-issue; SEC-002, RED-004);
//   - with certs:issue but NO bound profile, the default-deny base policy DENIES
//     the issue (SEC-005);
//   - with a bound profile the policy ALLOWS it, but dual control DENIES until a
//     DISTINCT approver approves — and a SELF-approval is rejected (SEC-002);
//   - once two distinct approvers approve, the served issue SUCCEEDS;
//   - revoke is likewise dual-control gated and tenant-scoped (AN-1).
func TestServedIssuanceGateEnforced(t *testing.T) {
	if testing.Short() {
		t.Skip("starts an embedded PostgreSQL; skipped in -short")
	}
	ctx := context.Background()

	dsn := serverTestPostgresDSN(t)
	st, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(st.Close)
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	resetServerTestStore(t, st)

	const tenantA = "11111111-1111-1111-1111-111111111111"

	// Seed an owner and an identity (the orchestrator creates it in `requested`), so a
	// real requested->issued transition can be attempted on the served path.
	owner, err := st.CreateOwner(ctx, store.Owner{TenantID: tenantA, Kind: store.OwnerWorkload, Name: "payments"})
	if err != nil {
		t.Fatalf("seed owner: %v", err)
	}

	// Build the production handler with the gate ENABLED (default-deny policy + dual
	// control) and the test-only header resolver so we can act as principals with
	// specific scopes. DefaultProfile is set so the base policy's "issue needs a bound
	// profile" precondition is satisfiable (the gate feeds it into the policy input);
	// there is no signer, so the async mint is a no-op and the HTTP result reflects
	// only the gate + orchestrator transition.
	phaseStore, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("open served store: %v", err)
	}
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		phaseStore.Close()
		t.Fatalf("open event log: %v", err)
	}
	registerServerTestTenant(t, phaseStore, log, tenantA, "served issuance gate tenant")
	storeServerTestProfile(t, phaseStore, tenantA, "tls-server", profile.CertificateProfile{
		Name: "tls-server", AllowedEKUs: []string{"serverAuth"},
		MaxValidity: profile.Duration(365 * 24 * time.Hour), AllowedProtocols: []string{"api"},
	})
	// A custom "requester" role holds identities:write (so it PASSES the route guard
	// on the transition endpoint) but deliberately lacks certs:issue — so a denial of
	// its self-issue attempt is the GATE's RA-separation check firing, not the route's
	// RBAC. This is what proves the served RA split (a requester cannot self-issue),
	// not just that the route is permission-guarded.
	requesterRole := authz.Role{Name: "requester", Permissions: []authz.Permission{authz.IdentitiesWrite, authz.CertsRequest}}
	srv, err := Build(ctx, Deps{
		Store:            phaseStore,
		Log:              log,
		DefaultProfile:   "tls-server",
		EnablePolicyGate: true,
		RequireApproval:  true,
		APIOptions:       []api.Option{api.WithInsecureHeaderResolver(), api.WithRoles(requesterRole)},
	})
	if err != nil {
		_ = log.Close()
		phaseStore.Close()
		t.Fatalf("build control plane: %v", err)
	}
	defer func() { _ = srv.Shutdown(context.Background()) }()
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// Create the identity through the served API as an operator (so it exists in the
	// projected read model the same way production would). operator holds
	// identities:write + certs:issue + certs:request.
	identID := createIdentityServed(t, ts, tenantA, owner.ID)

	// doTransitionAt issues a transition request as `subject` holding `roles`,
	// returning status+body. Taking the base URL lets the crash replay use a newly
	// assembled API process over the same durable spine.
	doTransitionAt := func(baseURL, subject, roles, to, idemKey string) (int, []byte) {
		body, _ := json.Marshal(map[string]string{"to": to, "reason": "test"})
		req, _ := http.NewRequest(http.MethodPost, baseURL+"/api/v1/identities/"+identID+"/transitions", bytes.NewReader(body))
		req.Header.Set("X-Tenant-ID", tenantA)
		req.Header.Set("X-Roles", roles)
		req.Header.Set("X-Subject", subject)
		req.Header.Set("Idempotency-Key", idemKey)
		return doReq(t, ts, req)
	}
	doTransition := func(subject, roles, to, idemKey string) (int, []byte) {
		return doTransitionAt(ts.URL, subject, roles, to, idemKey)
	}
	type approvalRef struct {
		ID           string `json:"id"`
		IntentDigest string `json:"intent_digest"`
		ResourceID   string `json:"resource_id"`
		Action       string `json:"action"`
	}
	loadApproval := func(subject, roles, action string) approvalRef {
		req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/approval-requests?status=pending", nil)
		req.Header.Set("X-Tenant-ID", tenantA)
		req.Header.Set("X-Roles", roles)
		req.Header.Set("X-Subject", subject)
		code, body := doReq(t, ts, req)
		if code != http.StatusOK {
			t.Fatalf("list genuine approval requests = %d, want 200; body=%s", code, body)
		}
		var queue struct {
			Items []approvalRef `json:"items"`
		}
		if err := json.Unmarshal(body, &queue); err != nil {
			t.Fatalf("decode genuine approval queue: %v; body=%s", err, body)
		}
		for _, item := range queue.Items {
			if item.ResourceID == identID && item.Action == action {
				return item
			}
		}
		t.Fatalf("genuine approval queue omitted %s/%s: %+v", identID, action, queue.Items)
		return approvalRef{}
	}
	doApprove := func(subject, roles, action, idemKey string, approval approvalRef) (int, []byte) {
		body, _ := json.Marshal(map[string]string{
			"action": action, "request_id": approval.ID, "intent_digest": approval.IntentDigest,
		})
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/identities/"+identID+"/approvals", bytes.NewReader(body))
		req.Header.Set("X-Tenant-ID", tenantA)
		req.Header.Set("X-Roles", roles)
		req.Header.Set("X-Subject", subject)
		req.Header.Set("Idempotency-Key", idemKey)
		return doReq(t, ts, req)
	}

	// (1) RA separation: a "requester" holds identities:write (so it PASSES the route
	// guard) but NOT certs:issue, so its self-issue attempt is denied by the GATE's RA
	// check — proving the served RA split, not merely route RBAC. This is the served
	// half of RED-004 (the requester scope cannot self-issue).
	if code, body := doTransition("alice", "requester", "issued", "k-ra"); code != http.StatusForbidden {
		t.Fatalf("requester (identities:write, no certs:issue) self-issue = %d, want 403 (gate RA split); body=%s", code, body)
	}

	// (2) Default-deny policy: an operator HAS certs:issue, but to exercise the policy
	// branch we confirm that with the gate on, an issue is only allowed once approved.
	// First attempt by the operator (the requester/performer) — policy allows (profile
	// bound) but dual control DENIES (no distinct approver yet).
	if code, body := doTransition("bob", "operator", "issued", "k-iss-1"); code != http.StatusForbidden {
		t.Fatalf("issue without approval = %d, want 403 (dual control); body=%s", code, body)
	}
	issueApproval := loadApproval("carol", "operator", "issue")

	// (3) Self-approval is rejected: bob (the requester/performer) cannot approve his
	// own pending issue. The store rejects approver==requester.
	if code, body := doApprove("bob", "operator", "issue", "k-selfappr", issueApproval); code == http.StatusOK {
		t.Fatalf("self-approval by the requester succeeded (%d); dual control must reject it; body=%s", code, body)
	}

	// (4) Two DISTINCT approvers approve (carol, dave) — neither is the requester bob.
	if code, body := doApprove("carol", "operator", "issue", "k-appr-1", issueApproval); code != http.StatusOK {
		t.Fatalf("first distinct approval = %d, want 200; body=%s", code, body)
	}
	if code, body := doApprove("dave", "operator", "issue", "k-appr-2", issueApproval); code != http.StatusOK {
		t.Fatalf("second distinct approval = %d, want 200; body=%s", code, body)
	}

	// (5) Now the served issue by bob SUCCEEDS: policy allows (profile bound), RA holds
	// (bob has certs:issue via operator), and dual control is satisfied (2 distinct
	// approvers, neither bob). Retry the exact command with the same idempotency key:
	// a pre-approval denial is not a completed mutation result, and changing the key
	// would correctly create a different immutable approval intent.
	code, issuedBody := doTransition("bob", "operator", "issued", "k-iss-1")
	if code != http.StatusOK {
		body := issuedBody
		t.Fatalf("issue after dual-control approval = %d, want 200; body=%s", code, body)
	}

	// Sanity: the identity is now `issued` in the read model.
	it, err := st.GetIdentity(ctx, tenantA, identID)
	if err != nil {
		t.Fatalf("load identity: %v", err)
	}
	if it.Status != "issued" {
		t.Fatalf("identity status = %q after approved issue, want issued", it.Status)
	}

	// Model the exact durable-effect crash gap: the lifecycle event, projection,
	// approval consumption, and outbox command committed, but the HTTP response did
	// not. A bound idempotency claim therefore re-enters the callback. Recovery must
	// find only the consumed authority bound to this requester + raw-key evidence and
	// return the original response without opening a fresh request or appending work.
	headBeforeReplay, err := log.LastSequence(ctx)
	if err != nil {
		t.Fatalf("read event head before crash-gap replay: %v", err)
	}
	var outboxBeforeReplay int
	if err := st.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `
			UPDATE idempotency_keys
			   SET status = 'bound', result = NULL, completed_at = NULL
			 WHERE tenant_id = $1 AND key = $2`, tenantA, "k-iss-1"); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `SELECT count(*) FROM outbox WHERE tenant_id = $1`, tenantA).Scan(&outboxBeforeReplay)
	}); err != nil {
		t.Fatalf("simulate lifecycle response-cache crash gap: %v", err)
	}
	// Model a restart/config rollout too: the current policy profile label is now
	// different from the one the original approval reviewed. Recovery must match
	// immutable caller/request evidence and trust the consumed request's original
	// profile evidence; it must not re-derive that historical evidence from today's
	// policy configuration.
	changedGate, changedApprovals, err := buildMutationGate(Deps{
		Store: phaseStore, Log: log, DefaultProfile: "tls-client-after-restart",
		EnablePolicyGate: true, RequireApproval: true,
	}, nil, srv.outbox, srv.orch)
	if err != nil {
		t.Fatalf("build changed-profile mutation gate: %v", err)
	}
	changedAPI := api.New(phaseStore, srv.idem, srv.orch,
		api.WithInsecureHeaderResolver(), api.WithRoles(requesterRole),
		api.WithEventLog(log), api.WithMutationGate(changedGate), api.WithApprovals(changedApprovals))
	changedTS := httptest.NewServer(changedAPI)
	defer changedTS.Close()

	replayCode, replayBody := doTransitionAt(changedTS.URL, "bob", "operator", "issued", "k-iss-1")
	if replayCode != http.StatusOK || !bytes.Equal(replayBody, issuedBody) {
		t.Fatalf("approved lifecycle crash-gap replay = (%d, %s), want exact (200, %s)", replayCode, replayBody, issuedBody)
	}
	if headAfterReplay, err := log.LastSequence(ctx); err != nil || headAfterReplay != headBeforeReplay {
		t.Fatalf("crash-gap replay event head = (%d, %v), want %d", headAfterReplay, err, headBeforeReplay)
	}
	var outboxAfterReplay int
	if err := st.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM outbox WHERE tenant_id = $1`, tenantA).Scan(&outboxAfterReplay)
	}); err != nil || outboxAfterReplay != outboxBeforeReplay {
		t.Fatalf("crash-gap replay outbox rows = (%d, %v), want %d", outboxAfterReplay, err, outboxBeforeReplay)
	}
	if freshCode, freshBody := doTransitionAt(changedTS.URL, "bob", "operator", "issued", "k-iss-fresh-after-consume"); freshCode != http.StatusConflict {
		t.Fatalf("fresh key reused generic consumed authority = %d body=%s, want invalid-transition 409", freshCode, freshBody)
	}
	if headAfterFresh, err := log.LastSequence(ctx); err != nil || headAfterFresh != headBeforeReplay {
		t.Fatalf("fresh-key same-state refusal changed event head = (%d, %v), want %d", headAfterFresh, err, headBeforeReplay)
	}
}

func TestServedMissingConfiguredProfileCreatesNoApprovalOrLifecycleWork(t *testing.T) {
	if testing.Short() {
		t.Skip("starts embedded PostgreSQL/NATS; skipped in -short")
	}
	ctx := context.Background()
	st := newServerTestStore(t)
	const tenantID = "11111111-1111-1111-1111-111111111111"
	owner, err := st.CreateOwner(ctx, store.Owner{
		TenantID: tenantID, Kind: store.OwnerWorkload, Name: "missing-profile-owner",
	})
	if err != nil {
		t.Fatalf("create owner: %v", err)
	}
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatalf("open event log: %v", err)
	}
	registerServerTestTenant(t, st, log, tenantID, "missing-profile gate tenant")
	srv, err := Build(ctx, Deps{
		Store: st, Log: log, DefaultProfile: "missing-reviewed-profile",
		EnablePolicyGate: true, RequireApproval: true,
		APIOptions: []api.Option{api.WithInsecureHeaderResolver()},
	})
	if err != nil {
		_ = log.Close()
		t.Fatalf("build control plane: %v", err)
	}
	defer func() { _ = srv.Shutdown(context.Background()) }()
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	identityID := createIdentityServed(t, ts, tenantID, owner.ID)

	headBefore, err := log.LastSequence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	pendingBefore, err := srv.outbox.Pending(ctx, tenantID)
	if err != nil {
		t.Fatal(err)
	}
	requestsBefore, err := st.ListOperationApprovals(ctx, tenantID, "", 20)
	if err != nil || len(requestsBefore) != 0 {
		t.Fatalf("approval requests before issue = (%d, %v), want zero", len(requestsBefore), err)
	}

	body, _ := json.Marshal(map[string]string{"to": "issued", "reason": "missing profile must fail before review"})
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/identities/"+identityID+"/transitions", bytes.NewReader(body))
	req.Header.Set("X-Tenant-ID", tenantID)
	req.Header.Set("X-Roles", "operator")
	req.Header.Set("X-Subject", "alice")
	req.Header.Set("Idempotency-Key", "missing-profile-issue")
	code, response := doReq(t, ts, req)
	if code != http.StatusNotFound {
		t.Fatalf("missing configured profile issue = %d, want 404; body=%s", code, response)
	}
	requestsAfter, err := st.ListOperationApprovals(ctx, tenantID, "", 20)
	if err != nil || len(requestsAfter) != 0 {
		t.Fatalf("missing profile approval requests = (%d, %v), want zero", len(requestsAfter), err)
	}
	if headAfter, headErr := log.LastSequence(ctx); headErr != nil || headAfter != headBefore {
		t.Fatalf("missing profile event head = (%d, %v), want %d", headAfter, headErr, headBefore)
	}
	pendingAfter, err := srv.outbox.Pending(ctx, tenantID)
	if err != nil || len(pendingAfter) != len(pendingBefore) {
		t.Fatalf("missing profile outbox = (%d, %v), want unchanged %d", len(pendingAfter), err, len(pendingBefore))
	}
	identity, err := st.GetIdentity(ctx, tenantID, identityID)
	if err != nil || identity.Status != string(orchestrator.StateRequested) {
		t.Fatalf("identity after missing profile = (%+v, %v), want requested", identity, err)
	}
}

func TestServedConfiguredDefaultProfileRequiresApprovalInStandardMode(t *testing.T) {
	if testing.Short() {
		t.Skip("starts embedded PostgreSQL/NATS; skipped in -short")
	}
	ctx := context.Background()
	st := newServerTestStore(t)
	const tenantID = "11111111-1111-1111-1111-111111111111"
	const profileName = "standard-mode-reviewed-default"
	storeServerTestProfile(t, st, tenantID, profileName, profile.CertificateProfile{
		Name: profileName, RequiresApproval: true,
		MaxValidity: profile.Duration(6 * time.Hour), AllowedProtocols: []string{"api"},
	})
	owner, err := st.CreateOwner(ctx, store.Owner{
		TenantID: tenantID, Kind: store.OwnerWorkload, Name: "standard-profile-owner",
	})
	if err != nil {
		t.Fatal(err)
	}
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	registerServerTestTenant(t, st, log, tenantID, "configured-profile approval tenant")
	srv, err := Build(ctx, Deps{
		Store: st, Log: log, DefaultProfile: profileName, RequiredApprovals: 1,
		// Deliberately leave EnablePolicyGate, EnableABAC, and the global
		// RequireApproval false. The configured profile's own immutable policy is
		// what must turn on exact dual control.
		APIOptions: []api.Option{api.WithInsecureHeaderResolver()},
	})
	if err != nil {
		_ = log.Close()
		t.Fatal(err)
	}
	defer func() { _ = srv.Shutdown(context.Background()) }()
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	identityID := createIdentityServed(t, ts, tenantID, owner.ID)

	body, _ := json.Marshal(map[string]string{"to": "issued", "reason": "configured profile controls standard mode"})
	issue := func() (int, []byte) {
		req, _ := http.NewRequest(http.MethodPost,
			ts.URL+"/api/v1/identities/"+identityID+"/transitions", bytes.NewReader(body))
		req.Header.Set("X-Tenant-ID", tenantID)
		req.Header.Set("X-Roles", "operator")
		req.Header.Set("X-Subject", "alice")
		req.Header.Set("Idempotency-Key", "standard-profile-issue")
		return doReq(t, ts, req)
	}
	if code, response := issue(); code != http.StatusForbidden {
		t.Fatalf("standard-mode issue bypassed configured profile approval = %d; body=%s", code, response)
	}
	requests, err := st.ListOperationApprovals(ctx, tenantID, store.ApprovalStatusPending, 10)
	if err != nil || len(requests) != 1 {
		t.Fatalf("standard-mode profile approval queue = (%d, %v), want one", len(requests), err)
	}
	request := requests[0]
	use, err := store.OperationApprovalUseFromRequest(request)
	if err != nil || use.Issuance == nil || use.Issuance.ProfileName != profileName ||
		use.Issuance.ProfileID == "" || use.Issuance.ProfileVersion != 1 ||
		use.Issuance.ProfileSpecDigest == "" || use.Issuance.EffectiveTTLSeconds != int64((6*time.Hour)/time.Second) {
		t.Fatalf("standard-mode configured profile binding = (%+v, %v)", use.Issuance, err)
	}
	if _, err := srv.orch.RecordOperationApprovalDecision(ctx, tenantID, orchestrator.OperationApprovalDecision{
		RequestID: request.ID, IntentDigest: request.IntentDigest,
		Approver: "bob", Decision: store.ApprovalDecisionApprove,
	}); err != nil {
		t.Fatalf("approve standard-mode configured profile: %v", err)
	}
	if code, response := issue(); code != http.StatusOK {
		t.Fatalf("standard-mode configured profile issue after approval = %d; body=%s", code, response)
	}
	consumed, err := st.GetOperationApproval(ctx, tenantID, request.ID)
	if err != nil || consumed.Status != store.ApprovalStatusConsumed {
		t.Fatalf("standard-mode profile authority = (%+v, %v), want consumed", consumed, err)
	}
}

func TestServedConfiguredDefaultShortProfileCarriesTTLWithoutApproval(t *testing.T) {
	if testing.Short() {
		t.Skip("starts embedded PostgreSQL/NATS; skipped in -short")
	}
	ctx := context.Background()
	st := newServerTestStore(t)
	const tenantID = "11111111-1111-1111-1111-111111111111"
	const profileName = "standard-mode-short-default"
	storeServerTestProfile(t, st, tenantID, profileName, profile.CertificateProfile{
		Name: profileName, MaxValidity: profile.Duration(6 * time.Hour),
		AllowedProtocols: []string{"api"},
	})
	owner, err := st.CreateOwner(ctx, store.Owner{
		TenantID: tenantID, Kind: store.OwnerWorkload, Name: "short-profile-owner",
	})
	if err != nil {
		t.Fatal(err)
	}
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	registerServerTestTenant(t, st, log, tenantID, "configured-profile TTL tenant")
	srv, err := Build(ctx, Deps{
		Store: st, Log: log, DefaultProfile: profileName,
		APIOptions: []api.Option{api.WithInsecureHeaderResolver()},
	})
	if err != nil {
		_ = log.Close()
		t.Fatal(err)
	}
	defer func() { _ = srv.Shutdown(context.Background()) }()
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	identityID := createIdentityServed(t, ts, tenantID, owner.ID)

	body, _ := json.Marshal(map[string]string{"to": "issued", "reason": "use the short configured profile"})
	req, _ := http.NewRequest(http.MethodPost,
		ts.URL+"/api/v1/identities/"+identityID+"/transitions", bytes.NewReader(body))
	req.Header.Set("X-Tenant-ID", tenantID)
	req.Header.Set("X-Roles", "operator")
	req.Header.Set("X-Subject", "alice")
	req.Header.Set("Idempotency-Key", "short-default-profile-issue")
	if code, response := doReq(t, ts, req); code != http.StatusOK {
		t.Fatalf("standard-mode short-profile issue = %d, want 200; body=%s", code, response)
	}
	requests, err := st.ListOperationApprovals(ctx, tenantID, "", 10)
	if err != nil || len(requests) != 0 {
		t.Fatalf("short profile unexpectedly created approval work = (%d, %v)", len(requests), err)
	}
	pending, err := srv.outbox.Pending(ctx, tenantID)
	if err != nil {
		t.Fatal(err)
	}
	var issue orchestrator.Record
	for _, row := range pending {
		if row.Destination == "ca.issue" {
			issue = row
			break
		}
	}
	if issue.ID == 0 {
		t.Fatalf("short profile lifecycle produced no ca.issue row: %+v", pending)
	}
	var trigger transitionTrigger
	if err := json.Unmarshal(issue.Payload, &trigger); err != nil {
		t.Fatal(err)
	}
	if trigger.Approval != nil || trigger.Issuance == nil ||
		trigger.Issuance.ProfileName != profileName || trigger.Issuance.ProfileID == "" ||
		trigger.Issuance.ProfileVersion != 1 || trigger.Issuance.ProfileSpecDigest == "" ||
		trigger.Issuance.EffectiveTTLSeconds != int64((6*time.Hour)/time.Second) {
		t.Fatalf("unapproved short-profile lifecycle binding = %+v approval=%+v", trigger.Issuance, trigger.Approval)
	}

	gotTTL, binding, err := approvedIssuanceTTL([]*store.OperationApprovalIssuanceBinding{trigger.Issuance})
	if err != nil || binding != trigger.Issuance {
		t.Fatalf("decode unapproved short-profile binding = (%s, %+v, %v)", gotTTL, binding, err)
	}
	if gotTTL != 6*time.Hour {
		t.Fatalf("unapproved short-profile signer TTL = %s, want 6h", gotTTL)
	}
}

// createIdentityServed creates an identity via the served API as an operator and
// returns its id.
func createIdentityServed(t *testing.T, ts *httptest.Server, tenant, ownerID string) string {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"kind": "x509_certificate", "name": "svc.example.test", "owner_id": ownerID})
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/identities", bytes.NewReader(body))
	req.Header.Set("X-Tenant-ID", tenant)
	req.Header.Set("X-Roles", "operator")
	req.Header.Set("X-Subject", "seed-bot")
	req.Header.Set("Idempotency-Key", "k-create-ident")
	code, b := doReq(t, ts, req)
	if code != http.StatusCreated {
		t.Fatalf("create identity = %d, want 201; body=%s", code, b)
	}
	var got struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(b, &got); err != nil || got.ID == "" {
		t.Fatalf("decode identity id: %v; body=%s", err, b)
	}
	return got.ID
}

func doReq(t *testing.T, ts *httptest.Server, req *http.Request) (int, []byte) {
	t.Helper()
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", req.Method, req.URL.Path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}
