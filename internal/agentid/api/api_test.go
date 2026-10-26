// SPDX-License-Identifier: BUSL-1.1

package api_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	agidapi "trstctl.com/trstctl/internal/agentid/api"
	"trstctl.com/trstctl/internal/agentid/delegation"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/crypto"
)

// TestRoutes_Surface asserts the AGID REST surface: the root-anchor provisioning routes,
// the two mutating journey routes, and receipt/credential/evidence reads exist with the expected
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
		{"POST /api/v1/agent-delegation/attestors", true, "200", authz.AgentsWrite},
		{"GET /api/v1/agent-delegation/attestors", false, "200", authz.AgentsRead},
		{"POST /api/v1/agent-delegation/issuances", true, "202", authz.AgentsWrite},
		{"GET /api/v1/agent-delegation/issuance", false, "200", authz.AgentsRead},
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
		"/api/v1/agent-delegation/attestors",
		"/api/v1/agent-delegation/issuances",
		"/api/v1/agent-delegation/issuance",
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

func TestOpenAPIRootAnchorRequiresOnePublicKeySource(t *testing.T) {
	raw, err := json.Marshal(agidapi.OpenAPISpec())
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Components struct {
			Schemas map[string]struct {
				OneOf []struct {
					Required []string `json:"required"`
				} `json:"oneOf"`
			} `json:"schemas"`
		} `json:"components"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	for _, schema := range []string{"AGIDRootAnchorRequest", "AGIDAttestorRequest"} {
		got := doc.Components.Schemas[schema].OneOf
		if len(got) != 2 || len(got[0].Required) != 1 || got[0].Required[0] != "public_pem" ||
			len(got[1].Required) != 1 || got[1].Required[0] != "public_der" {
			t.Fatalf("%s public key oneOf = %+v; want PEM or DER exactly once", schema, got)
		}
	}
}

func TestOpenAPIRequiredReadIdentifiers(t *testing.T) {
	raw, err := json.Marshal(agidapi.OpenAPISpec())
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Paths map[string]struct {
			Get struct {
				Parameters []struct {
					Name     string `json:"name"`
					In       string `json:"in"`
					Required bool   `json:"required"`
				} `json:"parameters"`
			} `json:"get"`
		} `json:"paths"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, route := range agidapi.Routes(nil) {
		if route.Method != "GET" || len(route.Query) == 0 {
			continue
		}
		checked++
		item, ok := doc.Paths[route.Path]
		if !ok {
			t.Fatalf("GET %s is missing from OpenAPI", route.Path)
		}
		for _, declared := range route.Query {
			if !declared.Required {
				t.Errorf("GET %s query %s is optional in served OpenAPI but required by the handler", route.Path, declared.Name)
			}
			found := false
			for _, param := range item.Get.Parameters {
				if param.Name == declared.Name && param.In == "query" {
					found = true
					if !param.Required {
						t.Errorf("GET %s query %s is optional in standalone OpenAPI but required by the handler", route.Path, declared.Name)
					}
				}
			}
			if !found {
				t.Errorf("GET %s query %s is missing from OpenAPI", route.Path, declared.Name)
			}
		}
	}
	if checked != 5 {
		t.Errorf("keyed AGID read routes = %d, want 5", checked)
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
	if iss.IssuanceID == "" || iss.Status != "queued" || iss.StatusURL == "" {
		t.Errorf("IssueChainBound ack = %+v, want a queued issuance id", iss)
	}
	issuance, err := svc.GetIssuance(ctx, "t", iss.IssuanceID)
	if err != nil || issuance.Found || issuance.Status != "not_found" {
		t.Errorf("nil-backed issuance status = %+v err=%v", issuance, err)
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
	svc := agidapi.NewServiceWithSignerFloors(nil, nil, nil, agidapi.SignerFloors{RootAnchors: provisioner})
	rootKey, err := crypto.NewSoftwareBackend().GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("generate public root for fixture: %v", err)
	}
	publicDER := rootKey.Public().DER

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

type rootReadbackProbe struct {
	publicDER       []byte
	authRef         string
	overrideAuthRef string
	readErr         error
}

func (p *rootReadbackProbe) ProvisionAgentRootAnchor(_ context.Context, _, _ string, publicDER []byte, authRef string) error {
	p.publicDER = append([]byte(nil), publicDER...)
	p.authRef = authRef
	return nil
}

func (p *rootReadbackProbe) ReadAgentRootAnchor(_ context.Context, _, _ string) ([]byte, string, error) {
	if p.readErr != nil {
		return nil, "", p.readErr
	}
	if p.overrideAuthRef != "" {
		return append([]byte(nil), p.publicDER...), p.overrideAuthRef, nil
	}
	return append([]byte(nil), p.publicDER...), p.authRef, nil
}

func TestService_RegisterRootAnchorNeedsExactSignerReadback(t *testing.T) {
	key, err := crypto.NewSoftwareBackend().GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	req := agidapi.RootAnchorRequest{KeyID: "root", PublicDER: key.Public().DER, AuthRef: "webauthn:credential"}
	if _, err := agidapi.NewServiceWithSignerFloors(nil, nil, nil, agidapi.SignerFloors{}).RegisterRootAnchor(t.Context(), "tenant", req); !errors.Is(err, agidapi.ErrRootAnchorSignerUnavailable) {
		t.Fatalf("missing signer = %v, want unavailable", err)
	}
	probe := &rootReadbackProbe{readErr: errors.New("signer floor unreachable")}
	svc := agidapi.NewServiceWithSignerFloors(nil, nil, nil, agidapi.SignerFloors{RootAnchors: probe})
	if _, err := svc.RegisterRootAnchor(t.Context(), "tenant", req); err == nil {
		t.Fatal("signer readback outage reported a provisioned root")
	}
	probe.readErr = nil
	probe.overrideAuthRef = "other-authenticator"
	if _, err := svc.RegisterRootAnchor(t.Context(), "tenant", req); !errors.Is(err, agidapi.ErrRootAnchorSignerReadback) {
		t.Fatalf("different signer binding = %v, want mismatch", err)
	}
	probe.overrideAuthRef = ""
	if resp, err := svc.RegisterRootAnchor(t.Context(), "tenant", req); err != nil || !resp.Provisioned {
		t.Fatalf("exact signer readback: %v", err)
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

type attestorReadbackProbe struct {
	publicDER      []byte
	method         string
	overrideMethod string
	readErr        error
	provisionErr   error
}

func (p *attestorReadbackProbe) ProvisionAgentAttestor(_ context.Context, _, _ string, publicDER []byte, method string) error {
	if p.provisionErr != nil {
		return p.provisionErr
	}
	p.publicDER = append([]byte(nil), publicDER...)
	p.method = method
	return nil
}

func (p *attestorReadbackProbe) ReadAgentAttestor(_ context.Context, _, _ string) ([]byte, string, error) {
	if p.readErr != nil {
		return nil, "", p.readErr
	}
	if p.overrideMethod != "" {
		return append([]byte(nil), p.publicDER...), p.overrideMethod, nil
	}
	return append([]byte(nil), p.publicDER...), p.method, nil
}

// A150: registering an attestor provisions the signer's tenant attestor floor and
// reports provisioned only after an exact, independent readback.
func TestService_RegisterAttestorProvisionsSignerFloor(t *testing.T) {
	floor := delegation.NewDurableAttestationTrustStore(t.TempDir())
	svc := agidapi.NewServiceWithSignerFloors(nil, nil, nil, agidapi.SignerFloors{Attestors: floor})
	key, err := crypto.NewSoftwareBackend().GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := svc.RegisterAttestor(t.Context(), "tenant-1", agidapi.AttestorRequest{
		KeyID: "tpm-verifier", Method: "tpm", PublicPEM: string(delegation.EncodeRootAnchorPEM(key.Public().DER)),
	})
	if err != nil || !resp.Provisioned || resp.Method != "tpm" || resp.Class != "hardware-tpm" {
		t.Fatalf("RegisterAttestor = %+v, %v", resp, err)
	}
	der, method, err := floor.ReadAgentAttestor(t.Context(), "tenant-1", "tpm-verifier")
	if err != nil || string(der) != string(key.Public().DER) || method != "tpm" {
		t.Fatalf("signer floor holds method %q, %v", method, err)
	}
	for name, req := range map[string]agidapi.AttestorRequest{
		"unknown method":   {KeyID: "a", Method: "made-up", PublicDER: key.Public().DER},
		"padded method":    {KeyID: "a", Method: " tpm", PublicDER: key.Public().DER},
		"unsafe key id":    {KeyID: "../a", Method: "tpm", PublicDER: key.Public().DER},
		"no key":           {KeyID: "a", Method: "tpm"},
		"two key sources":  {KeyID: "a", Method: "tpm", PublicDER: key.Public().DER, PublicPEM: "x"},
		"not a public key": {KeyID: "a", Method: "tpm", PublicDER: []byte("not a key")},
	} {
		if _, err := svc.RegisterAttestor(t.Context(), "tenant-1", req); !errors.Is(err, agidapi.ErrInvalidAttestorRequest) {
			t.Fatalf("%s = %v, want ErrInvalidAttestorRequest", name, err)
		}
	}
	listed, err := svc.ListAttestors(t.Context(), "tenant-1")
	if err != nil || listed.Count != 0 {
		t.Fatalf("list without a registry = %+v, %v", listed, err)
	}
}

func TestService_RegisterAttestorNeedsExactSignerReadback(t *testing.T) {
	key, err := crypto.NewSoftwareBackend().GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	req := agidapi.AttestorRequest{KeyID: "tpm-verifier", Method: "tpm", PublicDER: key.Public().DER}
	if _, err := agidapi.NewServiceWithSignerFloors(nil, nil, nil, agidapi.SignerFloors{}).RegisterAttestor(t.Context(), "tenant", req); !errors.Is(err, agidapi.ErrAttestorSignerUnavailable) {
		t.Fatalf("missing signer = %v, want unavailable", err)
	}
	probe := &attestorReadbackProbe{provisionErr: errors.New("signer floor unreachable")}
	svc := agidapi.NewServiceWithSignerFloors(nil, nil, nil, agidapi.SignerFloors{Attestors: probe})
	if _, err := svc.RegisterAttestor(t.Context(), "tenant", req); err == nil {
		t.Fatal("signer provisioning outage reported a provisioned attestor")
	}
	probe.provisionErr = nil
	probe.readErr = errors.New("signer floor unreachable")
	if _, err := svc.RegisterAttestor(t.Context(), "tenant", req); err == nil {
		t.Fatal("signer readback outage reported a provisioned attestor")
	}
	probe.readErr = nil
	probe.overrideMethod = "hsm"
	if _, err := svc.RegisterAttestor(t.Context(), "tenant", req); !errors.Is(err, agidapi.ErrAttestorSignerReadback) {
		t.Fatalf("different signer binding = %v, want mismatch", err)
	}
	probe.overrideMethod = ""
	if resp, err := svc.RegisterAttestor(t.Context(), "tenant", req); err != nil || !resp.Provisioned {
		t.Fatalf("exact signer readback: %+v, %v", resp, err)
	}
}
