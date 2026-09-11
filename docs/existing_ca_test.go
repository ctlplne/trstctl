// SPDX-License-Identifier: MPL-2.0

package docs

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"

	"trstctl.com/trstctl/internal/config"
)

func TestVaultOperatorExampleUsesAcceptedConfiguration(t *testing.T) {
	raw, err := os.ReadFile("examples/vault-external-ca.json")
	if err != nil {
		t.Fatal(err)
	}
	var example struct {
		ExternalCAs []config.ExternalCAConfig `json:"external_cas"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&example); err != nil {
		t.Fatal(err)
	}
	if len(example.ExternalCAs) != 1 || example.ExternalCAs[0].Type != "vaultpki" {
		t.Fatal("example must configure one Vault PKI authority")
	}
	if err := config.ValidateExternalCAs(example.ExternalCAs); err != nil {
		t.Fatalf("the documented operator configuration cannot start: %v", err)
	}
	ca := example.ExternalCAs[0]
	if ca.Mount == "" || ca.Role == "" || ca.Network.RootCAFile == "" || ca.Network.AllowInsecureHTTP {
		t.Fatal("Vault example must name its signing role and verified TLS trust")
	}
}
