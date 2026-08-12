// SPDX-License-Identifier: MPL-2.0

package api_test

import (
	"encoding/json"
	"testing"

	"trstctl.com/trstctl/internal/api"
)

func TestPKISecretContractsExposeMutuallyExclusiveCustodyModes(t *testing.T) {
	doc := fetchSpec(t)
	components := doc["components"].(map[string]any)
	schemas := components["schemas"].(map[string]any)
	request := schemas["PKISecretRequest"].(map[string]any)
	properties := request["properties"].(map[string]any)
	if properties["common_name"] == nil || properties["csr_pem"] == nil {
		t.Fatalf("native PKI request does not expose both custody modes: %#v", properties)
	}
	oneOf, ok := request["oneOf"].([]any)
	if !ok || len(oneOf) != 2 || !requiredOnly(oneOf[0], "common_name") || !requiredOnly(oneOf[1], "csr_pem") {
		t.Fatalf("native PKI request does not require exactly one custody selector: %#v", request["oneOf"])
	}
	response := schemas["PKISecret"].(map[string]any)
	if pkiContractContains(response["required"], "private_key") {
		t.Fatalf("CSR-first PKI response still requires private_key: %#v", response["required"])
	}

	raw, err := json.Marshal(api.VaultCompatContract())
	if err != nil {
		t.Fatal(err)
	}
	var vault map[string]any
	if err := json.Unmarshal(raw, &vault); err != nil {
		t.Fatal(err)
	}
	vaultPaths := vault["paths"].(map[string]any)
	if vaultPaths["/v1/pki/sign/{role}"] == nil || vaultPaths["/v1/pki/issue/{role}"] == nil {
		t.Fatalf("Vault/OpenBao contract does not expose safe sign and legacy issue paths: %#v", vaultPaths)
	}
	vaultSchemas := vault["components"].(map[string]any)["schemas"].(map[string]any)
	signData := vaultSchemas["VaultPKISignData"].(map[string]any)
	if signData["properties"].(map[string]any)["private_key"] != nil || pkiContractContains(signData["required"], "private_key") {
		t.Fatalf("Vault/OpenBao CSR-sign response exposes private_key: %#v", signData)
	}
}

func requiredOnly(value any, field string) bool {
	entry, ok := value.(map[string]any)
	return ok && len(entry) == 1 && pkiContractContains(entry["required"], field)
}

func pkiContractContains(value any, want string) bool {
	items, ok := value.([]any)
	if !ok {
		return false
	}
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}
