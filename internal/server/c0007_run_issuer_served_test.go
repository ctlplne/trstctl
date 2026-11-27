// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"net/http"
	"testing"

	"trstctl.com/trstctl/internal/config"
)

func TestC0007RunIssuerCannotApproveItsIssuanceRequest(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	x := a251Harness{t: t, h: h}
	issuer := seedScopedTokenSubject(t, h.store, h.tenant, "c0007-issuer",
		"access:read", "access:write", "access:bundle.run", "certs:request", "certs:read", "certs:issue")
	reviewer := seedScopedTokenSubject(t, h.store, h.tenant, "c0007-reviewer", "certs:issue")
	bundle := x.bundle(issuer, "bundle-a", "c0007-request", "certs:request", "certs:read")
	x.grant(issuer, "grant-a", bundle, "machine", "c0007-machine")
	second := x.bundle(issuer, "bundle-b", "c0007-secondary", "certs:read")
	x.grant(issuer, "grant-b", second, "machine", "c0007-machine")
	multi := x.run(issuer, "run-multi", map[string]any{
		"principal": "c0007-machine", "bundle_ids": []string{second, bundle}, "ttl_seconds": 600,
	})
	if len(multi.Run.BundleNames) != 2 {
		t.Fatalf("multi-bundle run lost its grants: %+v", multi.Run)
	}
	for _, tc := range []struct {
		name, principal string
	}{
		{"other-principal", "c0007-machine"},
		{"own-principal", "c0007-issuer"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.principal == "c0007-issuer" {
				x.grant(issuer, "grant-self", bundle, "machine", tc.principal)
			}
			run := x.run(issuer, "run-"+tc.name, map[string]any{
				"principal": tc.principal, "bundle_ids": []string{bundle}, "ttl_seconds": 600,
			})
			request := openRequest(t, h, run.Token, "ask-"+tc.name, "c0007.example.test")
			if request.Requester != "bundle-run:"+tc.principal {
				t.Fatalf("requester=%q, want run principal", request.Requester)
			}
			pam := &pamService{store: h.store}
			conflict, err := pam.pamApprovalPrincipalConflict(t.Context(), h.tenant, "c0007-issuer", request.Requester)
			if err != nil || !conflict {
				t.Fatalf("PAM manual review missed the run issuer: conflict=%t err=%v", conflict, err)
			}
			status, body := doBearer(t, h.ts, http.MethodPost,
				"/api/v1/issuance-requests/"+request.ID+"/approve", issuer, "vote-"+tc.name, nil)
			if status != http.StatusForbidden {
				t.Fatalf("run issuer approved its own request: %d %s; want 403", status, body)
			}
			status, body = doBearer(t, h.ts, http.MethodPost,
				"/api/v1/issuance-requests/"+request.ID+"/approve", reviewer, "independent-"+tc.name, nil)
			if status != http.StatusOK {
				t.Fatalf("independent reviewer could not approve: %d %s", status, body)
			}
		})
	}
}
