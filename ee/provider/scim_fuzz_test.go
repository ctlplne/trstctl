// SPDX-License-Identifier: LicenseRef-trstctl-EE

package provider

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
)

func FuzzAUD58ProviderSCIMBodiesNeverPanic(f *testing.F) {
	f.Add(byte(0), []byte(`{"userName":"casey@example.test","active":true,"roles":[{"value":"operator"}]}`))
	f.Add(byte(1), []byte(`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"active","value":false}]}`))
	f.Add(byte(2), []byte(`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"add","path":"members","value":[{"value":"op-1"}]}]}`))
	f.Fuzz(func(t *testing.T, route byte, body []byte) {
		if len(body) > 64<<10 {
			t.Skip()
		}
		now := time.Unix(1_786_614_400, 0).UTC()
		access := newAUD58AccessStore()
		access.identities["op-1"] = OperatorIdentity{
			ID: "op-1", ExternalID: "external-1", UserName: "operator@example.test",
			Role: OperatorOperator, Active: true, Source: "scim:fuzz", CreatedAt: now, UpdatedAt: now,
		}
		mutations := &aud58MutationSink{store: access}
		token := "aud58-scim-fuzz-token"
		handler := newSCIMHandler(&SCIMConfig{Tokens: []SCIMToken{{Name: "fuzz", TokenHash: crypto.SHA256Hex([]byte(token))}}},
			access, mutations, func() time.Time { return now })
		method, path := http.MethodPost, "/provider/scim/v2/Users"
		switch route % 3 {
		case 1:
			method, path = http.MethodPatch, "/provider/scim/v2/Users/op-1"
		case 2:
			method, path = http.MethodPatch, "/provider/scim/v2/Groups/operator"
		}
		req := httptest.NewRequest(method, path, strings.NewReader(string(body)))
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code < 100 || rec.Code > 599 {
			t.Fatalf("invalid HTTP status %d", rec.Code)
		}
	})
}
