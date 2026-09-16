// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/custody"
	"trstctl.com/trstctl/internal/protocols/spiffe"
	"trstctl.com/trstctl/internal/tenancy"
)

func TestTenantServiceStopsProtocolAndSPIFFESigning(t *testing.T) {
	for _, refusal := range []error{tenancy.ErrServiceUnavailable, errors.New("registry unavailable")} {
		t.Run(refusal.Error(), func(t *testing.T) {
			calls := 0
			check := tenancy.ServiceCheck(func(_ context.Context, tenant string) error {
				if tenant != "customer-a" {
					t.Fatalf("wrong authority tenant %q", tenant)
				}
				calls++
				return refusal
			})
			// No signer/idempotency spine is supplied. Reaching either would
			// return a different failure; admission must precede both.
			issuer := &protocolIssuer{tenantServiceCheck: check}
			if _, err := issuer.IssueProtocolLeaf(t.Context(), "customer-a", "est", "retry", nil, time.Minute); !errors.Is(err, refusal) {
				t.Fatalf("protocol = %v", err)
			}
			if _, err := issuer.issueProtocolLeafWithOrigin(t.Context(), "customer-a", "acme", "retry", nil, time.Minute, custody.OriginRequester); !errors.Is(err, refusal) {
				t.Fatalf("requester protocol = %v", err)
			}
			svid := tenantSPIFFEIssuer{tenantID: "customer-a", check: check}
			if _, err := svid.SignX509SVID(t.Context(), "spiffe://qa/workload", nil, time.Minute); !errors.Is(err, refusal) {
				t.Fatalf("X509 SVID = %v", err)
			}
			if _, err := svid.SignJWTSVID(t.Context(), "spiffe://qa/workload", []string{"qa"}, time.Minute); !errors.Is(err, refusal) {
				t.Fatalf("JWT SVID = %v", err)
			}
			if calls != 4 {
				t.Fatalf("admission calls = %d", calls)
			}
		})
	}
}

type countingTenantSVIDIssuer struct {
	spiffe.Issuer
	calls int
}

func (i *countingTenantSVIDIssuer) SignJWTSVID(context.Context, string, []string, time.Duration) (string, error) {
	i.calls++
	return "test-svid", nil
}

func TestTenantServiceRechecksEstablishedSPIFFEIssuer(t *testing.T) {
	active := true
	underlying := &countingTenantSVIDIssuer{}
	issuer := tenantSPIFFEIssuer{Issuer: underlying, tenantID: "customer-a", check: func(context.Context, string) error {
		if !active {
			return tenancy.ErrServiceUnavailable
		}
		return nil
	}}
	if _, err := issuer.SignJWTSVID(t.Context(), "spiffe://qa/workload", []string{"qa"}, time.Minute); err != nil {
		t.Fatal(err)
	}
	active = false
	if _, err := issuer.SignJWTSVID(t.Context(), "spiffe://qa/workload", []string{"qa"}, time.Minute); !errors.Is(err, tenancy.ErrServiceUnavailable) {
		t.Fatalf("suspended = %v", err)
	}
	active = true
	if _, err := issuer.SignJWTSVID(t.Context(), "spiffe://qa/workload", []string{"qa"}, time.Minute); err != nil {
		t.Fatal(err)
	}
	if underlying.calls != 2 {
		t.Fatalf("signatures = %d", underlying.calls)
	}
}

func TestTenantServiceFixedProtocolAdmission(t *testing.T) {
	for _, tc := range []struct {
		refusal error
		want    int
	}{{nil, http.StatusNoContent}, {tenancy.ErrServiceUnavailable, http.StatusForbidden}, {errors.New("private database detail"), http.StatusServiceUnavailable}} {
		calls := 0
		h := tenantProtocolAdmission(func(_ context.Context, tenant string) error {
			if tenant != "timestamp-customer" {
				t.Fatalf("tenant=%q", tenant)
			}
			return tc.refusal
		}, "timestamp-customer", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; w.WriteHeader(http.StatusNoContent) }))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/tsa", nil))
		if w.Code != tc.want {
			t.Fatalf("status=%d,want=%d", w.Code, tc.want)
		}
		if (calls == 1) != (tc.refusal == nil) {
			t.Fatalf("handler calls=%d,refusal=%v", calls, tc.refusal)
		}
	}
}
