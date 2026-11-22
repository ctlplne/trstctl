// SPDX-License-Identifier: BUSL-1.1

package api_test

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/orchestrator"
)

// autoApprovalRuleRecorder is a rule service that records the changes that
// reach it; every other PAM method is outside these tests.
type autoApprovalRuleRecorder struct {
	api.PAMService
	reached []string
}

func (r *autoApprovalRuleRecorder) SavePAMAutoApprovalRule(_ context.Context, _, actor string, in api.PAMAutoApprovalRule) (api.PAMAutoApprovalRule, error) {
	r.reached = append(r.reached, "save:"+actor)
	in.Revision, in.SavedBy = 1, actor
	return in, nil
}

func (r *autoApprovalRuleRecorder) ListPAMAutoApprovalRules(context.Context, string) ([]api.PAMAutoApprovalRule, error) {
	return nil, nil
}

func (r *autoApprovalRuleRecorder) DeletePAMAutoApprovalRule(_ context.Context, _, actor, _ string, _ int64) error {
	r.reached = append(r.reached, "delete:"+actor)
	return nil
}

// CR-001: saving or deleting an automatic approval rule is approval
// authority, as granting a standing approval is (OD-9). A principal that may
// request privileged access but not approve it, a token minted for its subject
// by someone else (F262) and an access bundle run are refused before the rule
// service is reached; a principal holding access:approve as well as
// access:write reaches it.
func TestAutoApprovalRuleChangesNeedApprovalAuthorityCR001(t *testing.T) {
	const tenant = "11111111-1111-4111-8111-111111111111"
	grants := func(perms ...authz.Permission) []authz.Grant {
		return []authz.Grant{{Role: authz.Role{Name: "cr001", Permissions: perms}, Scope: authz.Scope{TenantID: tenant}}}
	}
	approver := grants(authz.AccessRead, authz.AccessWrite, authz.AccessApprove)
	for _, tc := range []struct {
		name      string
		principal authz.Principal
		refusal   string // a phrase of the 403 detail; empty when the change reaches the service
	}{
		{"requester persona", authz.Principal{TenantID: tenant, Subject: "requester", Grants: grants(authz.AccessRead, authz.AccessWrite)}, "access:approve"},
		{"token minted by someone else", authz.Principal{TenantID: tenant, Subject: "custodian", Grants: approver, Delegated: true}, "minted"},
		{"access bundle run", authz.Principal{TenantID: tenant, Subject: "run", Grants: approver, RunID: "22222222-2222-4222-8222-222222222222"}, "run"},
		{"approver", authz.Principal{TenantID: tenant, Subject: "approver", Grants: approver}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rules := &autoApprovalRuleRecorder{}
			srv := httptest.NewServer(api.New(nil, orchestrator.NewMemoryIdempotency(), nil, api.WithPAM(rules),
				api.WithPrincipalResolver(func(*http.Request) (authz.Principal, error) { return tc.principal, nil })))
			defer srv.Close()
			id := uuid.NewString()
			for _, call := range []struct{ method, path, body string }{
				{http.MethodPut, "/api/v1/access/auto-approval-rules/" + id,
					`{"name":"cr001","revision":0,"applies_to":["session"],"target_ids":["orders"],"max_ttl_seconds":120,"enabled":true}`},
				{http.MethodDelete, "/api/v1/access/auto-approval-rules/" + id + "?revision=1", ""},
			} {
				req, err := http.NewRequest(call.method, srv.URL+call.path, strings.NewReader(call.body))
				if err != nil {
					t.Fatal(err)
				}
				req.Header.Set("Idempotency-Key", uuid.NewString())
				if call.body != "" {
					req.Header.Set("Content-Type", "application/json")
				}
				resp, err := srv.Client().Do(req)
				if err != nil {
					t.Fatal(err)
				}
				body, _ := io.ReadAll(resp.Body)
				_ = resp.Body.Close()
				if tc.refusal == "" {
					if resp.StatusCode != http.StatusOK {
						t.Errorf("%s by an approver = %d %s, want 200", call.method, resp.StatusCode, body)
					}
					continue
				}
				if resp.StatusCode != http.StatusForbidden || !bytes.Contains(body, []byte(tc.refusal)) {
					t.Errorf("%s by %s = %d %s, want 403 naming %q", call.method, tc.name, resp.StatusCode, body, tc.refusal)
				}
			}
			if tc.refusal != "" && len(rules.reached) != 0 {
				t.Errorf("%s reached the rule service: %v", tc.name, rules.reached)
			}
			if tc.refusal == "" && strings.Join(rules.reached, ",") != "save:approver,delete:approver" {
				t.Errorf("an approver's changes reached the rule service as %v", rules.reached)
			}
		})
	}
}

// CR-001: the served contract names access:approve beside access:write on
// both rule changes, so a client can tell which principals may make them.
func TestAutoApprovalRuleContractNamesApprovalAuthorityCR001(t *testing.T) {
	doc := fetchSpec(t)
	item := asMap(asMap(doc["paths"])["/api/v1/access/auto-approval-rules/{id}"])
	for _, method := range []string{"put", "delete"} {
		op := asMap(item[method])
		if op["x-trstctl-permission"] != "access:write" {
			t.Errorf("%s permission = %v, want access:write", method, op["x-trstctl-permission"])
		}
		named := false
		also, _ := op["x-trstctl-also-requires"].([]any)
		for _, raw := range also {
			if asMap(raw)["permission"] == "access:approve" {
				named = true
			}
		}
		if !named {
			t.Errorf("%s does not say it also needs access:approve: %v", method, op["x-trstctl-also-requires"])
		}
	}
}
