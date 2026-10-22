// SPDX-License-Identifier: LicenseRef-trstctl-EE

package provider

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/ee/enterpriseauth/scim"
	"trstctl.com/trstctl/internal/crypto"
)

// A89: the Provider plane accepts SCIM Bulk for User operations, with the
// same joiner/leaver semantics as the single routes, bulkId references, and
// per-operation idempotency so a replayed request appends nothing twice.
// Group operations are refused per operation, as the single routes refuse
// group remove/replace: a leaver is an explicit User change.
func TestProviderSCIMBulkAppliesUserOperationsInOrder(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	access := newAUD58AccessStore()
	mutations := &aud58MutationSink{store: access}
	rawToken := "a89-provider-scim-secret" // #nosec G101 -- deterministic non-deployable test bearer (CWE-798).
	h := NewHandler(Config{
		License: providerLicense(t, 10), Mutations: mutations, Access: access,
		Clock: func() time.Time { return now },
		SCIM:  &SCIMConfig{Tokens: []SCIMToken{{Name: "entra", TokenHash: crypto.SHA256Hex([]byte(rawToken))}}},
	})
	call := func(method, path, body, idem string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+rawToken)
		if idem != "" {
			req.Header.Set("Idempotency-Key", idem)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	if cfg := call(http.MethodGet, "/provider/scim/v2/ServiceProviderConfig", "", ""); cfg.Code != http.StatusOK || !strings.Contains(cfg.Body.String(), `"supported":true`) || !strings.Contains(cfg.Body.String(), `"maxOperations":100`) {
		t.Fatalf("ServiceProviderConfig = %d %s", cfg.Code, cfg.Body.String())
	}
	bulk := `{"schemas":["` + scim.SchemaBulkRequest + `"],"Operations":[
	 {"method":"POST","path":"/Users","bulkId":"casey","data":{"schemas":["` + scim.SchemaUser + `"],"externalId":"entra-1","userName":"casey@example.test","displayName":"Casey","roles":[{"value":"operator"}]}},
	 {"method":"POST","path":"/Users","bulkId":"dana","data":{"schemas":["` + scim.SchemaUser + `"],"externalId":"entra-2","userName":"dana@example.test","displayName":"Dana","roles":[{"value":"admin"}]}},
	 {"method":"PATCH","path":"/Users/bulkId:dana","data":{"schemas":["` + scim.SchemaPatchOp + `"],"Operations":[{"op":"replace","path":"active","value":false}]}},
	 {"method":"DELETE","path":"/Users/nobody"},
	 {"method":"PATCH","path":"/Groups/admin","data":{"schemas":["` + scim.SchemaPatchOp + `"],"Operations":[]}}
	]}`
	first := call(http.MethodPost, "/provider/scim/v2/Bulk", bulk, "bulk-1")
	if first.Code != http.StatusOK {
		t.Fatalf("bulk = %d %s", first.Code, first.Body.String())
	}
	var response scim.BulkResponse
	if err := json.Unmarshal(first.Body.Bytes(), &response); err != nil || len(response.Operations) != 5 {
		t.Fatalf("bulk response = %+v %v (%s)", response, err, first.Body.String())
	}
	for i, want := range []string{"201", "201", "200", "404", "400"} {
		if response.Operations[i].Status != want {
			t.Fatalf("operation %d = %+v, want %s", i, response.Operations[i], want)
		}
	}
	casey, err := access.ResolveOperator(t.Context(), "entra-1")
	if err != nil || !casey.Active || casey.Role != OperatorOperator || casey.Source != "scim:entra" {
		t.Fatalf("casey = %+v %v", casey, err)
	}
	dana, err := access.ResolveOperator(t.Context(), "entra-2")
	if err != nil || dana.Active || dana.DeprovisionedAt.IsZero() {
		t.Fatalf("dana after her bulkId patch = %+v %v, want deprovisioned", dana, err)
	}
	if response.Operations[0].Location != "http://example.com/provider/scim/v2/Users/"+casey.ID || response.Operations[0].BulkID != "casey" {
		t.Fatalf("casey's result = %+v", response.Operations[0])
	}
	events := len(mutations.seen)
	replay := call(http.MethodPost, "/provider/scim/v2/Bulk", bulk, "bulk-1")
	if replay.Code != http.StatusOK || len(mutations.seen) != events {
		t.Fatalf("replay = %d, events %d -> %d; a replay must append nothing", replay.Code, events, len(mutations.seen))
	}
	if refused := call(http.MethodPost, "/provider/scim/v2/Bulk", `{"schemas":["`+scim.SchemaBulkRequest+`"],"Operations":[]}`, "bulk-2"); refused.Code != http.StatusBadRequest {
		t.Fatalf("empty bulk = %d %s", refused.Code, refused.Body.String())
	}
}
