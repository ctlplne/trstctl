// SPDX-License-Identifier: MPL-2.0

package cli

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestPKISecretCommandCarriesCSRFirstBody(t *testing.T) {
	cmd, args, ok := matchCommand([]string{"secrets", "pki"})
	if !ok {
		t.Fatal("secrets pki did not resolve to a concrete command")
	}
	if !strings.Contains(strings.ToLower(cmd.Summary), "requester csr") || !strings.Contains(strings.ToLower(cmd.Summary), "deprecated") {
		t.Fatalf("secrets pki help does not explain both custody modes: %q", cmd.Summary)
	}
	const csr = "-----BEGIN CERTIFICATE REQUEST-----\nPUBLIC-CSR\n-----END CERTIFICATE REQUEST-----\n"
	bodyJSON, err := json.Marshal(map[string]any{"csr_pem": csr, "ttl_seconds": 900})
	if err != nil {
		t.Fatal(err)
	}
	path, _, body, _, err := buildRequest(cmd, append(args, "-f", "-"), strings.NewReader(string(bodyJSON)))
	if err != nil {
		t.Fatalf("build CSR-first request: %v", err)
	}
	if path != "/api/v1/secrets/pki" {
		t.Fatalf("path = %q, want /api/v1/secrets/pki", path)
	}
	var decoded map[string]any
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("decode request body: %v", err)
	}
	if decoded["csr_pem"] != csr || decoded["common_name"] != nil {
		t.Fatalf("CSR-first CLI body changed custody mode: %#v", decoded)
	}
}
