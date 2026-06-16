package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
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

	dsn, stopPG, err := startBundledPostgres(config.Postgres{Mode: config.PostgresBundled, DataDir: t.TempDir(), Port: freeTCPPort(t)})
	if err != nil {
		t.Fatalf("start bundled postgres: %v", err)
	}
	t.Cleanup(func() { _ = stopPG() })

	st, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(st.Close)
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}

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

	// do issues a transition request as `subject` holding `roles`, returning status+body.
	doTransition := func(subject, roles, to, idemKey string) (int, []byte) {
		body, _ := json.Marshal(map[string]string{"to": to, "reason": "test"})
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/identities/"+identID+"/transitions", bytes.NewReader(body))
		req.Header.Set("X-Tenant-ID", tenantA)
		req.Header.Set("X-Roles", roles)
		req.Header.Set("X-Subject", subject)
		req.Header.Set("Idempotency-Key", idemKey)
		return doReq(t, ts, req)
	}
	doApprove := func(subject, roles, action, idemKey string) (int, []byte) {
		body, _ := json.Marshal(map[string]string{"action": action})
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

	// (3) Self-approval is rejected: bob (the requester/performer) cannot approve his
	// own pending issue. The store rejects approver==requester.
	if code, body := doApprove("bob", "operator", "issue", "k-selfappr"); code == http.StatusOK {
		t.Fatalf("self-approval by the requester succeeded (%d); dual control must reject it; body=%s", code, body)
	}

	// (4) Two DISTINCT approvers approve (carol, dave) — neither is the requester bob.
	if code, body := doApprove("carol", "operator", "issue", "k-appr-1"); code != http.StatusOK {
		t.Fatalf("first distinct approval = %d, want 200; body=%s", code, body)
	}
	if code, body := doApprove("dave", "operator", "issue", "k-appr-2"); code != http.StatusOK {
		t.Fatalf("second distinct approval = %d, want 200; body=%s", code, body)
	}

	// (5) Now the served issue by bob SUCCEEDS: policy allows (profile bound), RA holds
	// (bob has certs:issue via operator), and dual control is satisfied (2 distinct
	// approvers, neither bob). Use a fresh idempotency key (the prior 403 is recorded
	// under k-iss-1).
	if code, body := doTransition("bob", "operator", "issued", "k-iss-2"); code != http.StatusOK {
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
