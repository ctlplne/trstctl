// SPDX-License-Identifier: BUSL-1.1

package api_test

// CR-151 served-route regression (review-2026-11/reads/S8b-2a.md).

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	agentapi "trstctl.com/trstctl/internal/agentid/api"
	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/editionseam"
	"trstctl.com/trstctl/internal/orchestrator"
)

const s8b2aTenant = "11111111-1111-1111-1111-111111111111"

// s8b2aFloors records what the API tries to register with the signer. The real
// signer requires independent local provisioning (CR-297); this fixture isolates
// the authorization check before that boundary.
type s8b2aFloors struct {
	mu        sync.Mutex
	anchors   map[string][]byte
	authRefs  map[string]string
	attestors map[string][]byte
	methods   map[string]string
}

func newS8b2aFloors() *s8b2aFloors {
	return &s8b2aFloors{anchors: map[string][]byte{}, authRefs: map[string]string{},
		attestors: map[string][]byte{}, methods: map[string]string{}}
}

func (f *s8b2aFloors) ProvisionAgentRootAnchor(_ context.Context, tenant, keyID string, der []byte, authRef string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.anchors[tenant+"/"+keyID] = append([]byte(nil), der...)
	f.authRefs[tenant+"/"+keyID] = authRef
	return nil
}

func (f *s8b2aFloors) ReadAgentRootAnchor(_ context.Context, tenant, keyID string) ([]byte, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	der, ok := f.anchors[tenant+"/"+keyID]
	if !ok {
		return nil, "", errors.New("absent")
	}
	return der, f.authRefs[tenant+"/"+keyID], nil
}

func (f *s8b2aFloors) ProvisionAgentAttestor(_ context.Context, tenant, keyID string, der []byte, method string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.attestors[tenant+"/"+keyID] = append([]byte(nil), der...)
	f.methods[tenant+"/"+keyID] = method
	return nil
}

func (f *s8b2aFloors) ReadAgentAttestor(_ context.Context, tenant, keyID string) ([]byte, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	der, ok := f.attestors[tenant+"/"+keyID]
	if !ok {
		return nil, "", errors.New("absent")
	}
	return der, f.methods[tenant+"/"+keyID], nil
}

// s8b2aSPKI is a syntactically valid Ed25519 SubjectPublicKeyInfo (fixed dummy key
// bytes; no private key exists or is needed for the route-level proof).
func s8b2aSPKI() []byte {
	prefix := []byte{0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00}
	return append(prefix, bytes.Repeat([]byte{0x42}, 32)...)
}

func s8b2aPost(h http.Handler, role, path, key, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", key)
	req.Header.Set("X-Tenant-ID", s8b2aTenant)
	req.Header.Set("X-Subject", "s8b2a-"+role)
	req.Header.Set("X-Roles", role)
	res := httptest.NewRecorder()
	h.ServeHTTP(res, req)
	return res
}

// Registering a root or HSM attestor needs explicit trust authority even when
// the caller has routine agents:write. The signer-local floor remains separate.
func TestS8b2aL1AgentsWriteAloneRegistersDelegationRootAndHSMAttestor(t *testing.T) {
	floors := newS8b2aFloors()
	opts, err := agentapi.NewAPIOptionsFactory()(editionseam.LicensedAPIOptionsDeps{
		AGIDRootAnchors: floors, AGIDAttestors: floors,
	})
	if err != nil {
		t.Fatal(err)
	}
	opts = append(opts,
		api.WithInsecureHeaderResolver(),
		api.WithRoles(authz.Role{Name: "fleet-enroller", Permissions: []authz.Permission{authz.AgentsRead, authz.AgentsWrite}}),
		api.WithRoles(authz.Role{Name: "trust-custodian", Permissions: []authz.Permission{authz.AgentsTrustManage}}),
	)
	served := api.New(nil, orchestrator.NewMemoryIdempotency(), nil, opts...)
	pub := base64.StdEncoding.EncodeToString(s8b2aSPKI())

	// Control: the route permission is enforced at all (viewer lacks agents:write).
	if res := s8b2aPost(served, "viewer", "/api/v1/agent-delegation/root-anchors", "s8b2a-viewer",
		`{"key_id":"viewer-root","public_der":"`+pub+`","auth_ref":"webauthn:x"}`); res.Code != http.StatusForbidden {
		t.Fatalf("control: viewer root-anchor registration = %d %s, want 403", res.Code, res.Body.String())
	}

	for _, role := range []string{"fleet-enroller", "cli"} {
		root := s8b2aPost(served, role, "/api/v1/agent-delegation/root-anchors", "s8b2a-root-"+role,
			`{"key_id":"self-root-`+role+`","public_der":"`+pub+`","auth_ref":"webauthn:never-verified"}`)
		att := s8b2aPost(served, role, "/api/v1/agent-delegation/attestors", "s8b2a-hsm-"+role,
			`{"key_id":"self-hsm-`+role+`","method":"hsm","public_der":"`+pub+`"}`)
		if root.Code != http.StatusForbidden || att.Code != http.StatusForbidden {
			t.Errorf("role %q (routine agents:write) registered trust roots: root-anchor = %d %s; hsm attestor = %d %s; "+
				"want 403 for both (a delegation root and an attestor are trust-placing decisions, not fleet work)",
				role, root.Code, strings.TrimSpace(root.Body.String()), att.Code, strings.TrimSpace(att.Body.String()))
		}
	}
	root := s8b2aPost(served, "trust-custodian", "/api/v1/agent-delegation/root-anchors", "s8b2a-custodian-root",
		`{"key_id":"reviewed-root","public_der":"`+pub+`","auth_ref":"operator:ceremony-record-1"}`)
	att := s8b2aPost(served, "trust-custodian", "/api/v1/agent-delegation/attestors", "s8b2a-custodian-attestor",
		`{"key_id":"reviewed-hsm","method":"hsm","public_der":"`+pub+`"}`)
	if root.Code != http.StatusOK || att.Code != http.StatusOK {
		t.Fatalf("explicit trust custodian registration: root = %d %s; attestor = %d %s; want 200 for both",
			root.Code, root.Body.String(), att.Code, att.Body.String())
	}
	floors.mu.Lock()
	defer floors.mu.Unlock()
	if len(floors.anchors) != 1 || len(floors.attestors) != 1 {
		t.Fatalf("routine roles reached signer floor: roots=%d attestors=%d; want one custodian binding each", len(floors.anchors), len(floors.attestors))
	}
	for k, ref := range floors.authRefs {
		t.Logf("signer root-anchor floor now holds caller-chosen root %s (auth_ref %q, never verified)", k, ref)
	}
	for k, m := range floors.methods {
		t.Logf("signer attestor floor now holds caller-chosen attestor %s for method %q", k, m)
	}
}
