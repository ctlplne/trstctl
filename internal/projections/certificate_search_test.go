// SPDX-License-Identifier: BUSL-1.1
package projections_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/orchestrator"
)

func TestCertificateInventorySearchFindsUnloadedRowsAndPreservesTenantPagination(t *testing.T) {
	s := newStore(t)
	srv := httptest.NewServer(api.New(s, orchestrator.NewIdempotency(s), nil, api.WithInsecureHeaderResolver()))
	defer srv.Close()
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	for i := 0; i < 25; i++ {
		c := sampleCert(tenantA, fmt.Sprintf("unrelated-%d", i), "CN=unrelated", now.Add(time.Hour))
		if _, err := s.UpsertCertificate(ctx, c); err != nil {
			t.Fatal(err)
		}
	}
	wanted := sampleCert(tenantA, strings.Repeat("ab", 32), "CN=Needle subject", now.Add(2*time.Hour))
	wanted.SANs = []string{"match.only.test"}
	wanted.Issuer = "CN=Needle Issuer"
	wanted.Serial = "e5fb00d5fb85fc7fcb568277cae0d382"
	wanted.DeploymentLocation = `owned_100%/tls`
	var err error
	wanted, err = s.UpsertCertificate(ctx, wanted)
	if err != nil {
		t.Fatal(err)
	}
	otherTenant := wanted
	otherTenant.TenantID = tenantB
	otherTenant, err = s.UpsertCertificate(ctx, otherTenant)
	if err != nil {
		t.Fatal(err)
	}
	get := func(tenant string, values url.Values) ([]any, string, int) {
		t.Helper()
		status, _, body := do(t, srv, "GET", "/api/v1/certificates?"+values.Encode(), reqOpts{tenant: tenant})
		result := decode(t, body)
		items, _ := result["items"].([]any)
		cursor, _ := result["next_cursor"].(string)
		return items, cursor, status
	}
	for _, q := range []string{wanted.Serial, strings.ToUpper(wanted.Fingerprint), wanted.ID, "NEEDLE SUBJECT", "match.only.test", "needle issuer", "100%", "owned_"} {
		t.Run(q, func(t *testing.T) {
			items, _, status := get(tenantA, url.Values{"q": {q}, "limit": {"2"}})
			if status != http.StatusOK || len(items) != 1 || items[0].(map[string]any)["id"] != wanted.ID {
				t.Fatalf("tenant search %q returned status=%d items=%v", q, status, items)
			}
		})
	}
	items, _, status := get(tenantB, url.Values{"q": {wanted.Serial}})
	if status != http.StatusOK || len(items) != 1 || items[0].(map[string]any)["id"] != otherTenant.ID {
		t.Fatal("tenant B search did not retain isolation")
	}
	items, _, status = get(tenantA, url.Values{"q": {"' OR true --"}})
	if status != http.StatusOK || len(items) != 0 {
		t.Fatal("query punctuation broadened search")
	}
	items, _, status = get(tenantA, url.Values{"q": {"match.only.test"}, "expiring_before": {now.Add(90 * time.Minute).Format(time.RFC3339)}})
	if status != http.StatusOK || len(items) != 0 {
		t.Fatal("search lost expiry filter")
	}
	for _, expiry := range []string{"", now.Add(3 * time.Hour).Format(time.RFC3339)} {
		seen := map[string]bool{}
		cursor := ""
		for pages := 0; pages < 15; pages++ {
			values := url.Values{"q": {"unrelated"}, "limit": {"3"}}
			if expiry != "" {
				values.Set("expiring_before", expiry)
			}
			if cursor != "" {
				values.Set("cursor", cursor)
			}
			items, next, status := get(tenantA, values)
			if status != http.StatusOK {
				t.Fatalf("search page status=%d", status)
			}
			for _, raw := range items {
				row := raw.(map[string]any)
				id := row["id"].(string)
				if seen[id] || id == wanted.ID || id == otherTenant.ID {
					t.Fatal("search pagination leaked or duplicated a row")
				}
				seen[id] = true
			}
			if next == "" {
				break
			}
			cursor = next
		}
		if len(seen) != 25 {
			t.Fatalf("search pages yielded %d of 25 rows", len(seen))
		}
	}
	for _, q := range []string{strings.Repeat("x", 257), "nul\x00query", string([]byte{0xff})} {
		_, _, status := get(tenantA, url.Values{"q": {q}})
		if status != http.StatusBadRequest {
			t.Fatalf("invalid query accepted: status=%d", status)
		}
	}
}
