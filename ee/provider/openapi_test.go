// SPDX-License-Identifier: LicenseRef-trstctl-EE

package provider

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"
)

func TestProviderOpenAPIReflectsAttachedRoutes(t *testing.T) {
	h := NewHandler(Config{License: providerLicense(t, 10)})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/provider/v1/openapi.json", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("Provider OpenAPI = %d: %s", w.Code, w.Body.String())
	}
	var doc struct {
		OpenAPI string `json:"openapi"`
		Paths   map[string]map[string]struct {
			OperationID string `json:"operationId"`
			Parameters  []struct {
				Name     string `json:"name"`
				Required bool   `json:"required"`
			} `json:"parameters"`
			Security []map[string][]string `json:"security"`
		} `json:"paths"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.OpenAPI != "3.1.0" || len(doc.Paths) < 20 {
		t.Fatalf("incomplete Provider OpenAPI: version=%q paths=%d", doc.OpenAPI, len(doc.Paths))
	}
	if _, ok := doc.Paths["/provider/v1/auth/saml/login"]; ok {
		t.Fatal("unconfigured SAML route was advertised")
	}
	if _, ok := doc.Paths["/provider/scim/v2/Users"]; ok {
		t.Fatal("unconfigured SCIM route was advertised")
	}
	if _, ok := doc.Paths["/provider/v1/openapi.json"]; ok {
		t.Fatal("spec endpoint must not describe itself as a customer operation")
	}
	for _, target := range []string{
		"post /provider/v1/tenants", "get /provider/v1/tenants",
		"get /provider/v1/tenants/{id}/brand", "put /provider/v1/tenants/{id}/brand",
		"get /provider/v1/tenants/{id}/usage-evidence", "post /provider/v1/breakglass/{id}/consent",
	} {
		method, path, _ := strings.Cut(target, " ")
		op, ok := doc.Paths[path][method]
		if !ok || op.OperationID == "" {
			t.Fatalf("missing documented Provider operation %s", target)
		}
	}
	for path, methods := range doc.Paths {
		for method, op := range methods {
			if method != "post" && method != "put" {
				continue
			}
			if !hasRequiredHeader(op.Parameters, "Idempotency-Key") {
				t.Errorf("%s %s lacks required Idempotency-Key", method, path)
			}
		}
	}
	// Keep the document tied to the real Provider dispatch. These patterns
	// extract every exact and customer-id route from handler.go's switch arms.
	source, err := os.ReadFile("handler.go")
	if err != nil {
		t.Fatal(err)
	}
	exact := regexp.MustCompile(`case r.Method == http.Method(Get|Post|Put) && r.URL.Path == "([^"]+)"`)
	for _, match := range exact.FindAllStringSubmatch(string(source), -1) {
		if match[2] == "/provider/v1/openapi.json" {
			continue
		}
		if strings.HasPrefix(match[2], "/provider/v1/auth/saml/") {
			continue // this fixture deliberately has no attached SAML service
		}
		method := strings.ToLower(match[1])
		if _, ok := doc.Paths[match[2]][method]; !ok {
			t.Errorf("served exact route absent from OpenAPI: %s %s", method, match[2])
		}
	}
	dynamic := regexp.MustCompile(`case r.Method == http.Method(Get|Post|Put) && strings.HasPrefix\(r.URL.Path, "([^"]+)"\) && strings.HasSuffix\(r.URL.Path, "([^"]+)"\)`)
	for _, match := range dynamic.FindAllStringSubmatch(string(source), -1) {
		method, path := strings.ToLower(match[1]), match[2]+"{id}"+match[3]
		if _, ok := doc.Paths[path][method]; !ok {
			t.Errorf("served customer route absent from OpenAPI: %s %s", method, path)
		}
	}
}

func TestProviderQuotaSchemaDoesNotPromisePerCustomerTenantCap(t *testing.T) {
	doc := providerOpenAPIDocument(false, false)
	schemas := doc["components"].(map[string]any)["schemas"].(map[string]any)
	for _, name := range []string{"ProviderQuota", "ProviderQuotaRequest"} {
		properties := schemas[name].(map[string]any)["properties"].(map[string]any)
		if _, ok := properties["max_tenants"]; ok {
			t.Errorf("%s promises an unenforced per-customer tenant cap", name)
		}
	}
}

func TestProviderOpenAPIIncludesConfiguredIdentityRoutes(t *testing.T) {
	doc := providerOpenAPIDocument(true, true)
	paths, ok := doc["paths"].(map[string]map[string]any)
	if !ok {
		t.Fatalf("Provider paths have unexpected type %T", doc["paths"])
	}
	for _, target := range []string{
		"get /provider/v1/auth/saml/login", "post /provider/v1/auth/saml/acs",
		"get /provider/v1/auth/saml/metadata", "get /provider/scim/v2/ServiceProviderConfig",
		"post /provider/scim/v2/Users", "get /provider/scim/v2/Users",
		"get /provider/scim/v2/Users/{id}", "put /provider/scim/v2/Users/{id}",
		"patch /provider/scim/v2/Users/{id}", "delete /provider/scim/v2/Users/{id}",
		"get /provider/scim/v2/Groups", "get /provider/scim/v2/Groups/{id}",
		"patch /provider/scim/v2/Groups/{id}",
		"get /provider/v1/tenants/{id}/breakglass",
	} {
		method, path, _ := strings.Cut(target, " ")
		if _, ok := paths[path][method]; !ok {
			t.Errorf("configured identity route absent from OpenAPI: %s", target)
		}
	}
	operationCount := 0
	for _, methods := range paths {
		operationCount += len(methods)
	}
	if len(paths) != 31 || operationCount != 39 {
		t.Fatalf("configured Provider/SCIM contract = %d paths / %d operations, want 31 / 39", len(paths), operationCount)
	}
	components := doc["components"].(map[string]any)
	schemas := components["schemas"].(map[string]any)
	encoded, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	for _, match := range regexp.MustCompile(`"\$ref":"#/components/schemas/([^"]+)"`).FindAllStringSubmatch(string(encoded), -1) {
		if _, ok := schemas[match[1]]; !ok {
			t.Errorf("unresolved schema reference %s", match[1])
		}
	}
	seen := map[string]bool{}
	for _, methods := range paths {
		for _, value := range methods {
			op := value.(map[string]any)
			id := op["operationId"].(string)
			if seen[id] {
				t.Errorf("duplicate operationId %s", id)
			}
			seen[id] = true
		}
	}
}

func hasRequiredHeader(params []struct {
	Name     string `json:"name"`
	Required bool   `json:"required"`
}, name string) bool {
	for _, item := range params {
		if item.Name == name && item.Required {
			return true
		}
	}
	return false
}
