// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/policy"
)

func TestCR024PolicyAuditOutageIsRetryableAtLifecycleGate(t *testing.T) {
	for _, tc := range []struct {
		name string
		gate MutationGate
	}{
		{name: "lifecycle", gate: MutationGate{Policy: fakePolicy{allow: true, err: policy.ErrDecisionAuditUnavailable}}},
		{name: "ABAC", gate: MutationGate{ABAC: &fakeABAC{err: policy.ErrDecisionAuditUnavailable}, Policy: fakePolicy{allow: true}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ge := asGateErr(t, tc.gate.check(t.Context(), principalWith("issuer", roleIssuer), gateTenant, "id-1", "issued", nil))
			if ge == nil || ge.status != http.StatusServiceUnavailable {
				t.Fatalf("audit outage must deny with retryable 503: %v", ge)
			}
		})
	}
}

func TestCR024PolicyAuditOutageIsRetryableAtReadGuard(t *testing.T) {
	reader := authz.Role{Name: "owner-reader", Permissions: []authz.Permission{authz.OwnersRead}}
	principal := principalWith("reader", reader)
	a := New(nil, nil, nil,
		WithRoles(reader),
		WithPrincipalResolver(func(*http.Request) (authz.Principal, error) { return principal, nil }),
		WithABACDenyOverlay(&fakeABAC{err: policy.ErrDecisionAuditUnavailable}, nil, nil),
	)
	rec := httptest.NewRecorder()
	a.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/owners", nil).WithContext(context.Background()))
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "retry") {
		t.Fatalf("audit outage must refuse read with retryable 503: HTTP %d %s", rec.Code, rec.Body.String())
	}
}
