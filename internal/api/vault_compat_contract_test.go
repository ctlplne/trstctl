package api

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/store"
)

var updateVaultCompatGoldens = flag.Bool("update-vault-compat-goldens", false, "regenerate Vault/OpenBao compatibility contract and response fixtures")

const (
	vaultCompatContractPath = "../../docs/contracts/vault-openbao-compat.openapi.json"
	vaultCompatFixturesPath = "testdata/vault_compat_response_fixtures.golden.json"
)

func TestVaultCompatContractGolden(t *testing.T) {
	canon, _ := canonicalVaultCompatContract(t)
	compareOrUpdateVaultCompatGolden(t, vaultCompatContractPath, canon)
}

func TestVaultCompatNoBreakingChange(t *testing.T) {
	oldRaw, err := os.ReadFile(vaultCompatContractPath)
	if err != nil {
		t.Fatalf("read Vault/OpenBao contract golden: %v", err)
	}
	var oldDoc, newDoc map[string]any
	if err := json.Unmarshal(oldRaw, &oldDoc); err != nil {
		t.Fatalf("unmarshal Vault/OpenBao contract golden: %v", err)
	}
	_, newDoc = canonicalVaultCompatContract(t)

	oldPaths := vaultContractMap(oldDoc["paths"])
	newPaths := vaultContractMap(newDoc["paths"])
	for path, oldItem := range oldPaths {
		newItem, ok := newPaths[path]
		if !ok {
			t.Errorf("breaking Vault/OpenBao contract drift: path %q was removed", path)
			continue
		}
		for method := range vaultContractMap(oldItem) {
			if !vaultContractHTTPMethod(method) {
				continue
			}
			if _, ok := vaultContractMap(newItem)[method]; !ok {
				t.Errorf("breaking Vault/OpenBao contract drift: operation %s %s was removed", strings.ToUpper(method), path)
			}
		}
	}

	oldSchemas := vaultContractMap(vaultContractMap(oldDoc["components"])["schemas"])
	newSchemas := vaultContractMap(vaultContractMap(newDoc["components"])["schemas"])
	for name, oldSchema := range oldSchemas {
		newSchema, ok := newSchemas[name]
		if !ok {
			t.Errorf("breaking Vault/OpenBao contract drift: schema %q was removed", name)
			continue
		}
		newProps := vaultContractMap(vaultContractMap(newSchema)["properties"])
		for _, required := range vaultContractStrings(vaultContractMap(oldSchema)["required"]) {
			if _, ok := newProps[required]; !ok {
				t.Errorf("breaking Vault/OpenBao contract drift: schema %q dropped required envelope field %q", name, required)
			}
		}
		oldRequired := vaultContractStringSet(vaultContractStrings(vaultContractMap(oldSchema)["required"]))
		for _, required := range vaultContractStrings(vaultContractMap(newSchema)["required"]) {
			if !oldRequired[required] {
				t.Errorf("breaking Vault/OpenBao contract drift: schema %q made field %q newly required", name, required)
			}
		}
		checkVaultCompatEnumsNotNarrowed(t, name, vaultContractMap(oldSchema), vaultContractMap(newSchema))
	}
}

func TestVaultCompatContractCoversRegisteredShimRoutes(t *testing.T) {
	_, doc := canonicalVaultCompatContract(t)
	paths := vaultContractMap(doc["paths"])
	if len(paths) == 0 {
		t.Fatal("Vault/OpenBao compatibility contract has no paths")
	}
	for _, rt := range vaultCompatRoutes {
		if strings.HasPrefix(rt.contractPath, "/api/v1") {
			t.Fatalf("Vault/OpenBao route %s is incorrectly documented in the native /api/v1 contract", rt.contractPath)
		}
		pathItem := vaultContractMap(paths[rt.contractPath])
		if len(pathItem) == 0 {
			t.Fatalf("Vault/OpenBao registered route %s %s missing from compatibility contract", rt.method, rt.contractPath)
		}
		op := vaultContractMap(pathItem[strings.ToLower(rt.method)])
		if len(op) == 0 {
			t.Fatalf("Vault/OpenBao registered route %s %s missing contract operation", rt.method, rt.contractPath)
		}
		if got := op["operationId"]; got != rt.operationID {
			t.Fatalf("Vault/OpenBao route %s %s operationId = %v, want %s", rt.method, rt.contractPath, got, rt.operationID)
		}
		responses := vaultContractMap(op["responses"])
		if len(responses) == 0 || responses[rt.successCode] == nil {
			t.Fatalf("Vault/OpenBao route %s %s missing success response %s", rt.method, rt.contractPath, rt.successCode)
		}
	}
}

func TestVaultCompatRegisteredRoutesRemainServed(t *testing.T) {
	h := New(nil, nil, nil)
	for _, rt := range vaultCompatRoutes {
		var body *strings.Reader
		if rt.sampleBody == "" {
			body = strings.NewReader("")
		} else {
			body = strings.NewReader(rt.sampleBody)
		}
		req := httptest.NewRequest(rt.method, rt.samplePath, body)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code == http.StatusNotFound {
			t.Fatalf("Vault/OpenBao registered route %s %s returned 404; the served shim and contract drifted", rt.method, rt.samplePath)
		}
	}
}

func TestVaultCompatResponseFixturesGolden(t *testing.T) {
	canon := canonicalVaultCompatFixtures(t)
	compareOrUpdateVaultCompatGolden(t, vaultCompatFixturesPath, canon)
}

func canonicalVaultCompatContract(t *testing.T) ([]byte, map[string]any) {
	t.Helper()
	raw, err := json.Marshal(VaultCompatContract())
	if err != nil {
		t.Fatalf("marshal Vault/OpenBao contract: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal Vault/OpenBao contract: %v", err)
	}
	canon, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatalf("canonicalize Vault/OpenBao contract: %v", err)
	}
	canon = append(canon, '\n')
	return canon, doc
}

func canonicalVaultCompatFixtures(t *testing.T) []byte {
	t.Helper()
	fixtures := vaultCompatFixtures(t)
	canon, err := json.MarshalIndent(fixtures, "", "  ")
	if err != nil {
		t.Fatalf("canonicalize Vault/OpenBao fixtures: %v", err)
	}
	canon = append(canon, '\n')
	return canon
}

func vaultCompatFixtures(t *testing.T) map[string]any {
	t.Helper()
	a := &API{}
	out := map[string]any{}

	health := httptest.NewRecorder()
	a.vaultHealth(health, httptest.NewRequest(http.MethodGet, "/v1/sys/health", nil))
	out["health"] = vaultCompatHTTPFixture(t, health)

	for _, tc := range []struct {
		name string
		path string
	}{
		{name: "mount_secret", path: "secret/data/payments/db"},
		{name: "mount_pki", path: "pki/issue/default"},
	} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/v1/sys/internal/ui/mounts/"+tc.path, nil)
		req.SetPathValue("path", tc.path)
		a.vaultMountInfo(rec, req)
		out[tc.name] = vaultCompatHTTPFixture(t, rec)
	}

	principal := authz.Principal{
		TenantID: "tenant-a",
		Subject:  "svc@example.test",
		Grants: []authz.Grant{{
			Role:  authz.BuiltinRoles()["admin"],
			Scope: authz.Scope{TenantID: "tenant-a"},
		}},
	}
	token := httptest.NewRecorder()
	tokenReq := httptest.NewRequest(http.MethodGet, "/v1/auth/token/lookup-self", nil)
	tokenReq = tokenReq.WithContext(context.WithValue(tokenReq.Context(), principalCtxKey, principal))
	a.vaultTokenLookupSelf(token, tokenReq)
	out["token_lookup_self"] = vaultCompatHTTPFixture(t, token)

	updated := time.Date(2026, 7, 2, 1, 2, 3, 4, time.UTC)
	kvRead := httptest.NewRecorder()
	a.writeVaultKVRead(kvRead, store.Secret{Name: "payments/db", Version: 2, UpdatedAt: updated}, []byte(`{"username":"payments","password":"redacted"}`))
	out["kv_v2_read_object"] = vaultCompatHTTPFixture(t, kvRead)

	contract := VaultCompatContract()
	out["kv_v2_put_request_schema"] = vaultCompatJSONValue(t, contract.Components.Schemas["VaultKVWriteRequest"])
	out["kv_v2_put_response_schema"] = vaultCompatJSONValue(t, contract.Components.Schemas["VaultKVWriteResponse"])
	out["pki_issue_request_schema"] = vaultCompatJSONValue(t, contract.Components.Schemas["VaultPKIIssueRequest"])
	out["pki_issue_response_schema"] = vaultCompatJSONValue(t, contract.Components.Schemas["VaultPKIIssueResponse"])

	return out
}

func vaultCompatHTTPFixture(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var body any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode Vault/OpenBao fixture body: %v\n%s", err, rec.Body.Bytes())
	}
	return map[string]any{
		"status": rec.Code,
		"body":   body,
	}
}

func vaultCompatJSONValue(t *testing.T, v any) any {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal Vault/OpenBao JSON value: %v", err)
	}
	var out any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal Vault/OpenBao JSON value: %v", err)
	}
	return out
}

func compareOrUpdateVaultCompatGolden(t *testing.T, path string, canon []byte) {
	t.Helper()
	if *updateVaultCompatGoldens {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, canon, 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote %s", path)
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s (regenerate with -update-vault-compat-goldens): %v", path, err)
	}
	if !bytes.Equal(want, canon) {
		t.Fatalf("Vault/OpenBao golden drifted from %s. If this additive change is intended, run: go test ./internal/api -run 'TestVaultCompat.*Golden' -update-vault-compat-goldens", path)
	}
}

func checkVaultCompatEnumsNotNarrowed(t *testing.T, schema string, oldSchema, newSchema map[string]any) {
	t.Helper()
	oldProps := vaultContractMap(oldSchema["properties"])
	newProps := vaultContractMap(newSchema["properties"])
	for field, oldProp := range oldProps {
		oldEnum := vaultContractStrings(vaultContractMap(oldProp)["enum"])
		if len(oldEnum) == 0 {
			continue
		}
		newEnum := vaultContractStringSet(vaultContractStrings(vaultContractMap(newProps[field])["enum"]))
		for _, v := range oldEnum {
			if !newEnum[v] {
				t.Errorf("breaking Vault/OpenBao contract drift: schema %q field %q removed enum value %q", schema, field, v)
			}
		}
	}
}

func vaultContractMap(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

func vaultContractStrings(v any) []string {
	raw, _ := v.([]any)
	out := make([]string, 0, len(raw))
	for _, elem := range raw {
		if s, ok := elem.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func vaultContractStringSet(ss []string) map[string]bool {
	out := make(map[string]bool, len(ss))
	for _, s := range ss {
		out[s] = true
	}
	return out
}

func vaultContractHTTPMethod(method string) bool {
	switch method {
	case "get", "post", "put", "delete", "patch":
		return true
	default:
		return false
	}
}
