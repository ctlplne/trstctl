// SPDX-License-Identifier: BUSL-1.1

package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/decommission/depstate"
	decstore "trstctl.com/trstctl/internal/decommission/store"
	"trstctl.com/trstctl/internal/eventspec"
	"trstctl.com/trstctl/internal/orchestrator"
)

// Missing tenant evidence must not become permission-looking retirement advice.
// Exercise the production factory and real PostgreSQL projection, including a
// foreign tenant and a genuinely complete dependency history as controls.
func TestRetirementChecklistRequiresTenantDependencyEvidence(t *testing.T) {
	cs := openStoreOn(t, "vdec_api_retirement_evidence")
	repo := decstore.New(cs)
	const foreignTenant = "22222222-2222-2222-2222-222222222222"
	foreign := []eventspec.Event{
		mustEncode(t, depstate.DependencyRegisteredV1{TenantID: foreignTenant, KeyID: "foreign-key", Dependent: dep(depstate.DependentCiphertext, "foreign-secret-reference")}, 1),
	}
	if err := repo.RebuildTenant(context.Background(), foreignTenant, foreign); err != nil {
		t.Fatal(err)
	}
	local := []eventspec.Event{
		mustEncode(t, depstate.DependencyRegisteredV1{TenantID: tenantA, KeyID: "blocked-key", Dependent: dep(depstate.DependentCredential, "active-leaf")}, 2),
		mustEncode(t, depstate.DependencyRegisteredV1{TenantID: tenantA, KeyID: "accounted-key", Dependent: dep(depstate.DependentCredential, "retired-leaf")}, 3),
		mustEncode(t, depstate.DependencyReleasedV1{TenantID: tenantA, KeyID: "accounted-key", Dependent: dep(depstate.DependentCredential, "retired-leaf"), Reason: "credential retired"}, 4),
	}
	if err := repo.RebuildTenant(context.Background(), tenantA, local); err != nil {
		t.Fatal(err)
	}
	served := newServedAPI(t, cs, orchestrator.NewOutbox(cs))
	var missingDetail string
	for _, key := range []string{"never-recorded", "foreign-key"} {
		t.Run(key, func(t *testing.T) {
			rr := httptest.NewRecorder()
			served.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/v1/ca/keys/"+key+"/retirement", nil))
			if rr.Code != http.StatusNotFound {
				t.Fatalf("missing tenant evidence returned %d: %s; want 404, never a clear checklist", rr.Code, rr.Body.String())
			}
			if !strings.HasPrefix(rr.Header().Get("Content-Type"), "application/problem+json") {
				t.Fatalf("missing evidence must use the API problem contract: %s", rr.Header().Get("Content-Type"))
			}
			var problem struct {
				Status int    `json:"status"`
				Detail string `json:"detail"`
			}
			if err := json.Unmarshal(rr.Body.Bytes(), &problem); err != nil {
				t.Fatal(err)
			}
			if problem.Status != http.StatusNotFound || !strings.Contains(problem.Detail, "dependency state") || !strings.Contains(problem.Detail, "verify the key ID") {
				t.Fatalf("missing actionable evidence explanation: %+v", problem)
			}
			if missingDetail == "" {
				missingDetail = problem.Detail
			} else if problem.Detail != missingDetail {
				t.Fatalf("foreign tenant existence changed the explanation: %q != %q", problem.Detail, missingDetail)
			}
			for _, forbidden := range []string{"foreign-secret-reference", foreignTenant, `"blocked"`, `"outstanding"`, "mint a destruction record"} {
				if strings.Contains(rr.Body.String(), forbidden) {
					t.Fatalf("missing evidence response disclosed %q: %s", forbidden, rr.Body.String())
				}
			}
		})
	}
	for _, tc := range []struct {
		key         string
		blocked     bool
		accounted   int
		outstanding int
	}{{"blocked-key", true, 0, 1}, {"accounted-key", false, 1, 0}} {
		t.Run(tc.key, func(t *testing.T) {
			rr := httptest.NewRecorder()
			served.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/v1/ca/keys/"+tc.key+"/retirement", nil))
			if rr.Code != http.StatusOK {
				t.Fatalf("recorded evidence = %d: %s", rr.Code, rr.Body.String())
			}
			var got api.RetirementChecklist
			if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
				t.Fatal(err)
			}
			if got.KeyID != tc.key || got.Blocked != tc.blocked || got.Total != 1 || got.Accounted != tc.accounted || len(got.Outstanding) != tc.outstanding {
				t.Fatalf("recorded evidence changed: %+v", got)
			}
		})
	}
}
