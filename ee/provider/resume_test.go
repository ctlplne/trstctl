// SPDX-License-Identifier: LicenseRef-trstctl-EE

package provider

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
)

func TestProviderResumeRequiresOwnGrantAndSurvivesReplay(t *testing.T) {
	ctx := context.Background()
	st := openProviderStore(t)
	truncateProviderAuthority(t, st)
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir(), SyncAlways: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	runtime := NewAuthorityRuntime(st, log)
	id := CustomerID("resume-customer")
	grants := &mutableDelegations{set: fullyDelegated("op-1", id)}
	store := NewPGStore(st)
	h := NewHandler(Config{License: providerLicense(t, 10), Store: store,
		Mutations: runtime.Mutations, Idempotency: orchestrator.NewIdempotency(st),
		Authenticator: authorityAuthenticator{}, Delegations: grants,
		Clock: func() time.Time { return time.Date(2026, 9, 16, 19, 0, 0, 0, time.UTC) },
	})
	request := func(path, key, body string, want int) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer requester")
		req.Header.Set("Idempotency-Key", key)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != want {
			t.Fatalf("%s = %d/%s, want %d", path, w.Code, w.Body.String(), want)
		}
		return w
	}
	base := "/provider/v1/tenants/" + id
	request("/provider/v1/tenants", "resume-provision", `{"slug":"resume-customer","name":"Resume customer"}`, http.StatusCreated)
	request(base+"/suspend", "resume-pause", `{}`, http.StatusNoContent)
	grants.set = StaticDelegations{{OperatorID: "op-1", CustomerID: id, Operations: []Operation{OpRead, OpSuspend}}}
	request(base+"/resume", "resume-refused", `{}`, http.StatusForbidden)
	if tenant, err := store.Tenant(ctx, id); err != nil || tenant.Status != TenantSuspended {
		t.Fatalf("refusal changed customer: %+v/%v", tenant, err)
	}
	grants.set = fullyDelegated("op-1", id)
	request(base+"/resume", "resume-refused", `{}`, http.StatusForbidden)
	request(base+"/resume", "resume-allowed", `{}`, http.StatusNoContent)
	before, err := log.LastSequence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	again := request(base+"/resume", "resume-allowed", `{}`, http.StatusNoContent)
	if again.Header().Get("Idempotent-Replayed") != "true" {
		t.Fatal("resume retry was not marked as replayed")
	}
	after, err := log.LastSequence(ctx)
	if err != nil || after != before {
		t.Fatalf("resume retry appended: %d -> %d/%v", before, after, err)
	}
	if tenant, err := store.Tenant(ctx, id); err != nil || tenant.Status != TenantActive {
		t.Fatalf("resume not projected: %+v/%v", tenant, err)
	}
	truncateProviderAuthority(t, st)
	if err := projections.New(st, projections.WithEventProjection(NewAuthorityProjection(st))).Project(ctx, log); err != nil {
		t.Fatal(err)
	}
	if tenant, err := store.Tenant(ctx, id); err != nil || tenant.Status != TenantActive {
		t.Fatalf("resume not rebuilt from events: %+v/%v", tenant, err)
	}
	request(base+"/offboard", "resume-offboard", `{}`, http.StatusNoContent)
	request(base+"/resume", "resume-after-offboard", `{}`, http.StatusConflict)
	if tenant, err := store.Tenant(ctx, id); err != nil || tenant.Status != TenantOffboarded {
		t.Fatalf("offboarded customer resurrected: %+v/%v", tenant, err)
	}
}

func TestProviderResumeAuthorityIsSeparateFromSuspend(t *testing.T) {
	for _, operation := range []Operation{OpSuspend, OpResume} {
		h := NewHandler(Config{License: providerLicense(t, 10),
			Authenticator: consoleAuthorityAuth{providerOperator("op-1")},
			Delegations:   StaticDelegations{{OperatorID: "op-1", CustomerID: "alpha", Operations: []Operation{operation}}},
		})
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/provider/v1/auth/session", nil))
		want := `"resume":false`
		if operation == OpResume {
			want = `"resume":true`
		}
		if !strings.Contains(w.Body.String(), want) {
			t.Fatalf("%s authority lacks %s: %s", operation, want, w.Body.String())
		}
	}
}
