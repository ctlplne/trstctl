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
	"trstctl.com/trstctl/internal/policy"
)

type emergencyResponderRecorder struct {
	api.PAMService
	actors []string
}

type emergencyResponderABAC struct{ denied string }

func (a emergencyResponderABAC) EvaluateDeny(_ context.Context, in policy.ABACInput) (policy.ABACDecision, error) {
	return policy.ABACDecision{Deny: in.Permission == a.denied, Reason: "custodian change window closed"}, nil
}

func TestEmergencyResponderChangesHonorAdditionalABACCR106(t *testing.T) {
	const tenant = "11111111-1111-4111-8111-111111111111"
	principal := authz.Principal{TenantID: tenant, Subject: "custodian", Grants: []authz.Grant{{
		Role:  authz.Role{Name: "custodian", Permissions: []authz.Permission{authz.AccessWrite, authz.AccessApprove, authz.AccessTargetsWrite}},
		Scope: authz.Scope{TenantID: tenant},
	}}}
	for _, permission := range []authz.Permission{authz.AccessApprove, authz.AccessTargetsWrite} {
		t.Run(string(permission), func(t *testing.T) {
			recorder := &emergencyResponderRecorder{}
			srv := httptest.NewServer(api.New(nil, orchestrator.NewMemoryIdempotency(), nil, api.WithPAM(recorder),
				api.WithABACDenyOverlay(emergencyResponderABAC{denied: string(permission)}, nil, nil),
				api.WithPrincipalResolver(func(*http.Request) (authz.Principal, error) { return principal, nil })))
			defer srv.Close()
			req, err := http.NewRequest(http.MethodPut, srv.URL+"/api/v1/access/emergency/responders", strings.NewReader(`{"subjects":["oncall"]}`))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Idempotency-Key", uuid.NewString())
			resp, err := srv.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusForbidden || !bytes.Contains(body, []byte("custodian change window closed")) || len(recorder.actors) != 0 {
				t.Fatalf("ABAC denial of %s: status=%d body=%s actors=%v", permission, resp.StatusCode, body, recorder.actors)
			}
		})
	}
}

func (r *emergencyResponderRecorder) SetPAMEmergencyResponders(_ context.Context, _, actor string, subjects []string) ([]string, error) {
	r.actors = append(r.actors, actor)
	return subjects, nil
}

func (r *emergencyResponderRecorder) ListPAMEmergencyResponders(context.Context, string) ([]string, error) {
	return nil, nil
}

func (r *emergencyResponderRecorder) OpenPAMEmergencySession(context.Context, string, string, string, api.PAMSessionRequest) (api.PAMSession, error) {
	return api.PAMSession{}, nil
}

func (r *emergencyResponderRecorder) ListPAMEmergencyGrants(context.Context, string) ([]api.PAMEmergencyGrant, error) {
	return nil, nil
}

func (r *emergencyResponderRecorder) ReviewPAMEmergencyGrant(context.Context, string, string, string, string, string) (api.PAMEmergencyGrant, error) {
	return api.PAMEmergencyGrant{}, nil
}

// CR-106: editing the list grants quorum-free emergency access. It needs
// target configuration and approval authority, an independent human author,
// and a token that belongs to its own subject.
func TestEmergencyResponderChangesNeedIndependentCustodianCR106(t *testing.T) {
	const tenant = "11111111-1111-4111-8111-111111111111"
	grants := func(perms ...authz.Permission) []authz.Grant {
		return []authz.Grant{{Role: authz.Role{Name: "cr106", Permissions: perms}, Scope: authz.Scope{TenantID: tenant}}}
	}
	custodian := grants(authz.AccessWrite, authz.AccessApprove, authz.AccessTargetsWrite)
	for _, tc := range []struct {
		name      string
		principal authz.Principal
		subjects  string
		refusal   string
	}{
		{"access writer", authz.Principal{TenantID: tenant, Subject: "operator", Grants: grants(authz.AccessWrite)}, `["oncall"]`, "access:approve"},
		{"approver without target authority", authz.Principal{TenantID: tenant, Subject: "approver", Grants: grants(authz.AccessWrite, authz.AccessApprove)}, `["oncall"]`, "access:targets.write"},
		{"delegated token", authz.Principal{TenantID: tenant, Subject: "custodian", Grants: custodian, Delegated: true}, `["oncall"]`, "minted"},
		{"bundle run", authz.Principal{TenantID: tenant, Subject: "custodian", Grants: custodian, RunID: uuid.NewString()}, `["oncall"]`, "bundle run"},
		{"self named", authz.Principal{TenantID: tenant, Subject: "Custodian@Ops.example", Grants: custodian}, `[" custodian@ops.EXAMPLE "]`, "yourself"},
		{"independent custodian", authz.Principal{TenantID: tenant, Subject: "custodian", Grants: custodian}, `["oncall"]`, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			recorder := &emergencyResponderRecorder{}
			srv := httptest.NewServer(api.New(nil, orchestrator.NewMemoryIdempotency(), nil, api.WithPAM(recorder),
				api.WithPrincipalResolver(func(*http.Request) (authz.Principal, error) { return tc.principal, nil })))
			defer srv.Close()
			req, err := http.NewRequest(http.MethodPut, srv.URL+"/api/v1/access/emergency/responders", strings.NewReader(`{"subjects":`+tc.subjects+`}`))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Idempotency-Key", uuid.NewString())
			resp, err := srv.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if tc.refusal != "" {
				if resp.StatusCode != http.StatusForbidden || !bytes.Contains(body, []byte(tc.refusal)) || len(recorder.actors) != 0 {
					t.Fatalf("list changed by %s: status=%d body=%s actors=%v", tc.name, resp.StatusCode, body, recorder.actors)
				}
				return
			}
			if resp.StatusCode != http.StatusOK || strings.Join(recorder.actors, ",") != "custodian" {
				t.Fatalf("independent custodian: status=%d body=%s actors=%v", resp.StatusCode, body, recorder.actors)
			}
		})
	}
}

func TestEmergencyResponderContractNamesCustodianAuthorityCR106(t *testing.T) {
	doc := fetchSpec(t)
	op := asMap(asMap(asMap(doc["paths"])["/api/v1/access/emergency/responders"])["put"])
	if op["x-trstctl-permission"] != "access:write" {
		t.Fatalf("route permission = %v", op["x-trstctl-permission"])
	}
	got := map[string]bool{}
	also, _ := op["x-trstctl-also-requires"].([]any)
	for _, raw := range also {
		got[asMap(raw)["permission"].(string)] = true
	}
	if !got["access:approve"] || !got["access:targets.write"] {
		t.Fatalf("responder-list contract omits custodian permissions: %v", also)
	}
}
