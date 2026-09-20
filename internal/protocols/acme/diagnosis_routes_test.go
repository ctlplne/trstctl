// SPDX-License-Identifier: BUSL-1.1

package acme

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/enrollmentdiag"
)

func TestDiagnosisUsesActualACMEResourceRoutes(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		path     string
		step     enrollmentdiag.Step
		identity string
	}{
		{"/acme/order/14/finalize", enrollmentdiag.StepIssue, "order:14"},
		{"/acme/order/14", enrollmentdiag.StepOrder, "order:14"},
		{"/acme/chal/abc", enrollmentdiag.StepValidation, "challenge:abc"},
		{"/acme/cert/42", enrollmentdiag.StepIssue, "certificate:42"},
		{"/acme/authz/abc", enrollmentdiag.StepAuthorize, "authorization:abc"},
		{"/acme/acct/7", enrollmentdiag.StepAccount, "account:7"},
		{"/acme/acct/7/orders", enrollmentdiag.StepOrder, "account:7"},
		{"/acme/order/challenge", enrollmentdiag.StepOrder, "order:challenge"},
		{"/acme/order/14/finalize/extra", "", ""},
		{"/acme/order//finalize", "", ""},
		{"/acme/new-order-suffix", "", ""},
		{"/unserved/acme/order/14", "", ""},
	} {
		t.Run(tc.path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, tc.path, nil)
			if got := acmeStepForPath(req); got != tc.step {
				t.Errorf("step = %q, want %q", got, tc.step)
			}
			if got := acmeIdentityRef(req); got != tc.identity {
				t.Errorf("identity = %q, want %q", got, tc.identity)
			}
		})
	}
}

func FuzzACMEDiagnosticRoute(f *testing.F) {
	for _, seed := range []string{"14", "challenge", "finalize", "", "a/b", "x?new-order", "\x00"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, id string) {
		req := &http.Request{URL: &url.URL{Path: "/acme/order/" + id + "/finalize"}}
		step, identity := acmeDiagnosticRoute(req)
		if id != "" && !strings.Contains(id, "/") {
			if step != enrollmentdiag.StepIssue || identity != "order:"+id {
				t.Fatalf("resource ID changed route interpretation: %q %q", step, identity)
			}
		} else if step != "" || identity != "" {
			t.Fatal("unmounted path was classified")
		}
	})
}
