// SPDX-License-Identifier: BUSL-1.1

package api_test

import (
	"context"
	"encoding/json"
	"testing"

	agidapi "trstctl.com/trstctl/internal/agentid/api"
	"trstctl.com/trstctl/internal/agentid/delegation"
	"trstctl.com/trstctl/internal/authz"
)

// TestRoutes_Surface asserts the AGID REST surface: the root-anchor provisioning routes,
// the two mutating journey routes, and the three read routes exist with the expected
// methods, success codes, mutation flags, and permissions. This locks the contract the
// cmd/trstctl attach exposes (the
// reachability entry points for the two AGID user journeys) without a datastore.
func TestRoutes_Surface(t *testing.T) {
	routes := agidapi.Routes(nil)
	byPath := map[string]struct {
		method     string
		mutation   bool
		successVal string
		perm       authz.Permission
		found      bool
	}{}
	for _, rt := range routes {
		key := rt.Method + " " + rt.Path
		byPath[key] = struct {
			method     string
			mutation   bool
			successVal string
			perm       authz.Permission
			found      bool
		}{rt.Method, rt.Mutation, rt.SuccessCode, rt.Permission, true}
	}

	want := []struct {
		key      string
		mutation bool
		success  string
		perm     authz.Permission
	}{
		{"POST /api/v1/agent-delegation/root-anchors", true, "200", authz.AgentsWrite},
		{"GET /api/v1/agent-delegation/root-anchors", false, "200", authz.AgentsRead},
		{"POST /api/v1/agent-delegation/issuances", true, "202", authz.AgentsWrite},
		{"POST /api/v1/agent-delegation/revocations", true, "202", authz.AgentsWrite},
		{"GET /api/v1/agent-delegation/credential", false, "200", authz.AgentsRead},
		{"GET /api/v1/agent-delegation/chain", false, "200", authz.AgentsRead},
		{"GET /api/v1/agent-delegation/revocations/incomplete-jobs", false, "200", authz.AgentsRead},
		{"GET /api/v1/agent-delegation/revocations/evidence", false, "200", authz.AgentsRead},
	}
	if len(routes) != len(want) {
		t.Fatalf("route count = %d, want %d", len(routes), len(want))
	}
	for _, w := range want {
		got, ok := byPath[w.key]
		if !ok {
			t.Fatalf("route %q missing", w.key)
		}
		if got.mutation != w.mutation {
			t.Errorf("route %q mutation = %v, want %v", w.key, got.mutation, w.mutation)
		}
		if got.successVal != w.success {
			t.Errorf("route %q success = %q, want %q", w.key, got.successVal, w.success)
		}
		if got.perm != w.perm {
			t.Errorf("route %q permission = %q, want %q", w.key, got.perm, w.perm)
		}
	}
}

// TestOpenAPI_Surface asserts the AGID OpenAPI 3.1 document renders, carries the AGID
// paths, and documents the Idempotency-Key header on every mutation (AN-5), mirroring the
// PCAS golden test's sanity checks. It does not pin a checked-in golden (kept lean), but it
// enforces the contract the release conformance gate depends on.
func TestOpenAPI_Surface(t *testing.T) {
	got, err := json.MarshalIndent(agidapi.OpenAPISpec(), "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(got, &doc); err != nil {
		t.Fatal(err)
	}
	if doc["openapi"] != "3.1.0" {
		t.Fatalf("openapi version = %v, want 3.1.0", doc["openapi"])
	}
	paths, _ := doc["paths"].(map[string]any)
	for _, p := range []string{
		"/api/v1/agent-delegation/root-anchors",
		"/api/v1/agent-delegation/issuances",
		"/api/v1/agent-delegation/revocations",
		"/api/v1/agent-delegation/credential",
		"/api/v1/agent-delegation/chain",
		"/api/v1/agent-delegation/revocations/incomplete-jobs",
		"/api/v1/agent-delegation/revocations/evidence",
	} {
		if _, ok := paths[p]; !ok {
			t.Fatalf("path %q missing from the AGID OpenAPI document", p)
		}
	}
	for _, rt := range agidapi.Routes(nil) {
		if !rt.Mutation {
			continue
		}
		item := paths[rt.Path].(map[string]any)
		op := item[lower(rt.Method)].(map[string]any)
		params, _ := op["parameters"].([]any)
		if !hasIdempotencyHeader(params) {
			t.Fatalf("mutation %s %s does not document the Idempotency-Key header", rt.Method, rt.Path)
		}
	}
}

// TestDestinations_Stable asserts the AGID outbox destination constants have their exact
// wire strings. These are the strings the orchestrator worker drains, duplicated there; a
// drift would silently break the two journeys (an enqueued message no handler drains).
func TestDestinations_Stable(t *testing.T) {
	if agidapi.IssuanceRequestDestination != "agentid.issue-chain-bound" {
		t.Errorf("IssuanceRequestDestination = %q", agidapi.IssuanceRequestDestination)
	}
	if agidapi.RevocationDirectiveDestination != "agentid.revoke-directive" {
		t.Errorf("RevocationDirectiveDestination = %q", agidapi.RevocationDirectiveDestination)
	}
}

// TestService_NilBackedReadsAreSafe asserts the read models fail soft (empty, no panic)
// when the service is built without a store — the Community/unlicensed shape. The mutating
// paths still return an acknowledgment (the outbox enqueue is skipped without a store).
func TestService_NilBackedReadsAreSafe(t *testing.T) {
	svc := agidapi.NewService(nil, nil, nil)
	ctx := context.Background()

	chain, err := svc.FetchChain(ctx, "t", "cred:1")
	if err != nil {
		t.Fatalf("FetchChain: %v", err)
	}
	if chain.Count != 0 || len(chain.Records) != 0 {
		t.Errorf("FetchChain on nil store = %+v, want empty", chain)
	}

	cred, err := svc.FetchCredential(ctx, "t", "cred:1")
	if err != nil {
		t.Fatalf("FetchCredential: %v", err)
	}
	if cred.Found || len(cred.CredentialDER) != 0 {
		t.Errorf("FetchCredential on nil store = %+v, want empty", cred)
	}

	inc, err := svc.IncompleteJobs(ctx, "t", "dir:1")
	if err != nil {
		t.Fatalf("IncompleteJobs: %v", err)
	}
	if inc.Count != 0 {
		t.Errorf("IncompleteJobs on nil store = %+v, want empty", inc)
	}

	ev, err := svc.RevocationEvidence(ctx, "t", "dir:1")
	if err != nil {
		t.Fatalf("RevocationEvidence: %v", err)
	}
	if ev.Terminal || ev.JobCount != 0 || len(ev.Artifact) != 0 {
		t.Errorf("RevocationEvidence on nil store = %+v, want empty", ev)
	}

	roots, err := svc.ListRootAnchors(ctx, "t")
	if err != nil {
		t.Fatalf("ListRootAnchors: %v", err)
	}
	if roots.Count != 0 || len(roots.Anchors) != 0 {
		t.Errorf("ListRootAnchors on nil store = %+v, want empty", roots)
	}

	iss, err := svc.IssueChainBound(ctx, "t", agidapi.IssueChainBoundRequest{AgentID: "a"})
	if err != nil {
		t.Fatalf("IssueChainBound: %v", err)
	}
	if iss.IssuanceID == "" || iss.Status != "queued" {
		t.Errorf("IssueChainBound ack = %+v, want a queued issuance id", iss)
	}

	rev, err := svc.Revoke(ctx, "t", agidapi.RevokeRequest{Subject: "s", Reason: "compromise"})
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if rev.DirectiveID == "" || rev.Status != "queued" {
		t.Errorf("Revoke ack = %+v, want a queued directive id", rev)
	}
}

func TestService_RegisterRootAnchorProvisionsSignerFloor(t *testing.T) {
	dir := t.TempDir()
	provisioner := delegation.NewDurableAnchorStore(dir)
	svc := agidapi.NewServiceWithRootAnchorProvisioner(nil, nil, nil, provisioner)
	publicDER := []byte{1, 2, 3, 4}

	resp, err := svc.RegisterRootAnchor(context.Background(), "tenant-1", agidapi.RootAnchorRequest{
		KeyID:     "root-key",
		PublicPEM: string(delegation.EncodeRootAnchorPEM(publicDER)),
		AuthRef:   "webauthn:credential-1",
	})
	if err != nil {
		t.Fatalf("RegisterRootAnchor: %v", err)
	}
	if !resp.Provisioned {
		t.Fatalf("RegisterRootAnchor response = %+v, want provisioned", resp)
	}
	anchor, err := provisioner.GetRootAnchor("tenant-1", "root-key")
	if err != nil {
		t.Fatalf("GetRootAnchor: %v", err)
	}
	if string(anchor.PublicDER) != string(publicDER) || anchor.AuthRef != "webauthn:credential-1" {
		t.Fatalf("provisioned anchor = %+v, want DER %v and auth ref", anchor, publicDER)
	}
}

func lower(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 'a' - 'A'
		}
	}
	return string(b)
}

func hasIdempotencyHeader(params []any) bool {
	for _, p := range params {
		m, _ := p.(map[string]any)
		if m["name"] == "Idempotency-Key" && m["in"] == "header" {
			return true
		}
	}
	return false
}
