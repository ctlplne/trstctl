// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
)

func TestGuardDenialAuditUsesVerifiedPrincipalAndStaticRoute(t *testing.T) {
	a := New(nil, nil, nil)
	principal := authz.Principal{TenantID: "11111111-1111-1111-1111-111111111111", Subject: "reader"}
	a.principal = func(*http.Request) (authz.Principal, error) { return principal, nil }
	count := 0
	a.denialAudit.appendDecision = func(ctx context.Context, tenant string, decision orchestrator.AuthzDecision) error {
		count++
		actor, ok := events.ActorFromContext(ctx)
		if !ok || actor.Subject != "reader" || tenant != principal.TenantID || decision.Actor != "reader" || decision.Permission != string(authz.AccessWrite) || decision.Target != "PUT /api/v1/access/members/{subject}" || decision.Decision != "deny" {
			t.Errorf("bad decision: %+v actor=%+v tenant=%s", decision, actor, tenant)
		}
		return nil
	}
	req := httptest.NewRequest(http.MethodPut, "/api/v1/access/members/private-path-canary?token=private-query-canary", strings.NewReader(`{"password":"private-body-canary"}`))
	rec := httptest.NewRecorder()
	a.ServeHTTP(rec, req)
	if rec.Code != 403 || count != 1 || rec.Header().Get("X-Trstctl-Audit-Status") != "recorded" {
		t.Fatalf("denial=%d count=%d audit=%q", rec.Code, count, rec.Header().Get("X-Trstctl-Audit-Status"))
	}
	for _, test := range []struct {
		name             string
		invalidPrincipal bool
		tenant           string
		want             int
	}{{"forged tenant", false, "22222222-2222-2222-2222-222222222222", 403}, {"unauthenticated", true, "", 401}} {
		t.Run(test.name, func(t *testing.T) {
			a.principal = func(*http.Request) (authz.Principal, error) {
				if test.invalidPrincipal {
					return authz.Principal{}, errors.New("bad credential")
				}
				return principal, nil
			}
			req := httptest.NewRequest(http.MethodPut, "/api/v1/access/members/reader", nil)
			req.Header.Set("X-Tenant-ID", test.tenant)
			rec := httptest.NewRecorder()
			a.ServeHTTP(rec, req)
			if rec.Code != test.want || count != 1 || rec.Header().Get("X-Trstctl-Audit-Status") != "" {
				t.Fatalf("untrusted request entered tenant audit: status=%d count=%d", rec.Code, count)
			}
		})
	}
}

func TestGuardDenialAuditAdmissionAndFailureAreBounded(t *testing.T) {
	principal := authz.Principal{TenantID: "tenant-a", Subject: "reader"}
	request := httptest.NewRequest(http.MethodPost, "/private-path?secret=redacted", nil)
	request.Pattern = "POST /api/v1/owners"
	t.Run("separate rate budget", func(t *testing.T) {
		a := New(nil, nil, nil, WithSpecialRouteAbuseLimits(SpecialRouteAbuseLimits{PerToken: 2}))
		calls := 0
		a.denialAudit.appendDecision = func(context.Context, string, orchestrator.AuthzDecision) error { calls++; return nil }
		for i := 0; i < 100; i++ {
			want := "rate_limited"
			if i < 2 {
				want = "recorded"
			}
			if got := a.denialAudit.record(request, principal, authz.OwnersWrite); got != want {
				t.Fatalf("request %d status=%s want=%s", i, got, want)
			}
		}
		if calls != 2 {
			t.Fatalf("event writes=%d", calls)
		}
		if allowed, _ := a.specialAbuse.allow(specialRouteAbuseRequest{Source: requestClientIP(request), TokenKey: principal.TenantID + "\x00" + principal.Subject, TenantID: principal.TenantID}); !allowed {
			t.Fatal("denied calls exhausted login/enrollment limiter")
		}
	})
	t.Run("no queue while all slots occupied", func(t *testing.T) {
		a := newAuthzDenialAudit(SpecialRouteAbuseLimits{}, nil)
		a.appendDecision = func(context.Context, string, orchestrator.AuthzDecision) error {
			t.Error("busy admission called writer")
			return nil
		}
		if cap(a.slots) != authzDenialAuditConcurrency {
			t.Fatalf("wrong concurrency cap=%d", cap(a.slots))
		}
		for i := 0; i < cap(a.slots); i++ {
			a.slots <- struct{}{}
		}
		if got := a.record(request, principal, authz.OwnersWrite); got != "busy" {
			t.Fatalf("status=%s", got)
		}
	})
	for _, mode := range []string{"append error", "timeout"} {
		t.Run(mode, func(t *testing.T) {
			a := New(nil, nil, nil)
			a.principal = func(*http.Request) (authz.Principal, error) { return principal, nil }
			a.denialAudit.timeout = 5 * time.Millisecond
			a.denialAudit.appendDecision = func(ctx context.Context, _ string, _ orchestrator.AuthzDecision) error {
				if mode == "timeout" {
					<-ctx.Done()
					return ctx.Err()
				}
				return errors.New("audit offline")
			}
			rec := httptest.NewRecorder()
			a.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/owners", nil))
			if rec.Code != 403 || rec.Header().Get("X-Trstctl-Audit-Status") != "unavailable" || len(a.denialAudit.slots) != 0 {
				t.Fatalf("failure changed authorization or leaked slot: status=%d audit=%s slots=%d", rec.Code, rec.Header().Get("X-Trstctl-Audit-Status"), len(a.denialAudit.slots))
			}
		})
	}
}
