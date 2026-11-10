// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

// A234-L3: audit segment downloads were limited per tenant only, six a
// minute in one bucket, so one caller could spend the tenant's budget and
// lock its other auditors out. Each caller now has its own six a minute,
// taken before the tenant's, and the tenant as a whole thirty: a caller over
// its limit is refused per caller while another caller still downloads, and
// the tenant's ceiling still holds across callers.
func TestServedAuditDownloadLimitIsPerCallerA234L3(t *testing.T) {
	ctx := context.Background()
	const tenant = "6b7c8d9e-0f1a-4b2c-8d3e-4f5a6b7c8d9e"
	st := newServerTestStore(t)
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	if err := st.UpsertTenant(ctx, store.Tenant{TenantID: tenant, Name: "archive limits"}); err != nil {
		t.Fatal(err)
	}
	registerServerTestTenant(t, st, log, tenant, "archive limits")
	if _, err := log.Append(ctx, events.Event{ID: "history-a234l3", TenantID: tenant, Type: "audit.test", Data: []byte(`{"reason":"a234l3 history"}`)}); err != nil {
		t.Fatal(err)
	}
	key, err := jose.GenerateRSASigningKey("archive-download-limits")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	srv, err := Build(ctx, Deps{Store: st, Log: log, AuditSigningKey: key, AuditArchiveDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })
	segment := seedTenantAuditSegment(t, log, st, key, srv.audit, tenant, dir)
	download := func(token string) (int, string) {
		request := httptest.NewRequest(http.MethodGet, "/api/v1/audit/archives/"+segment, nil)
		request.Header.Set("Authorization", "Bearer "+token)
		response := httptest.NewRecorder()
		srv.Handler().ServeHTTP(response, request)
		return response.Code, response.Body.String()
	}
	callers := make([]string, 6)
	for i := range callers {
		callers[i] = seedServedAPIToken(t, ctx, st, tenant, fmt.Sprintf("auditor-%d@example.invalid", i), []string{string(authz.AuditArchiveRead)})
	}

	// The first caller runs out of its own six.
	served, limited := 0, ""
	for i := 0; i < 8 && limited == ""; i++ {
		code, body := download(callers[0])
		switch code {
		case http.StatusOK:
			served++
		case http.StatusTooManyRequests:
			limited = body
		default:
			t.Fatalf("download %d = %d %s", i, code, body)
		}
	}
	if served < 6 || limited == "" {
		t.Fatalf("the first caller downloaded %d and was never refused; want its own six, then a refusal", served)
	}
	// Another auditor of the same tenant still downloads.
	if code, body := download(callers[1]); code != http.StatusOK {
		t.Fatalf("a second caller after the first spent its limit = %d %s; one caller locked the tenant out", code, body)
	}
	if !strings.Contains(limited, "limited per caller") {
		t.Fatalf("the first caller's refusal = %q; want it to say the limit is per caller", limited)
	}
	// The tenant's own ceiling still holds across callers.
	tenantLimited := false
	for _, caller := range callers[1:] {
		for i := 0; i < 6 && !tenantLimited; i++ {
			code, body := download(caller)
			if code == http.StatusTooManyRequests && strings.Contains(body, "limited per tenant") {
				tenantLimited = true
			} else if code != http.StatusOK && code != http.StatusTooManyRequests {
				t.Fatalf("download = %d %s", code, body)
			}
		}
	}
	if !tenantLimited {
		t.Fatal("six callers downloading six each never reached the tenant's ceiling")
	}
}
