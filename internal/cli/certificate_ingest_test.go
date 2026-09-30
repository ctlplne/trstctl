// SPDX-License-Identifier: BUSL-1.1

package cli_test

import (
	"encoding/json"
	"encoding/pem"
	"net/http"
	"os"
	"testing"

	"trstctl.com/trstctl/internal/cli"
)

func TestCertificateIngestAcceptsDocumentedPEMFileAndJSONBody(t *testing.T) {
	pemBytes, err := os.ReadFile("../../deploy/demo/lab/certs/pebble.minica.crt")
	if err != nil {
		t.Fatal(err)
	}

	var captured capture
	srv := mockServer(t, http.StatusCreated, `{"id":"imported-cert"}`, &captured)
	env := cli.Env{Server: srv.URL, Token: "inventory-token", Tenant: "tenant-a", HTTPClient: srv.Client()}

	code, _, stderr := run(t, []string{"certificates", "ingest", "-f", "../../deploy/demo/lab/certs/pebble.minica.crt"}, env, "")
	if code != 0 || stderr != "" {
		t.Fatalf("PEM import = exit %d stderr=%q", code, stderr)
	}
	if captured.Method != http.MethodPost || captured.Path != "/api/v1/certificates" || captured.Header.Get("Idempotency-Key") == "" {
		t.Fatalf("PEM import request = %s %s key=%q", captured.Method, captured.Path, captured.Header.Get("Idempotency-Key"))
	}
	var request struct {
		PEM string `json:"pem"`
	}
	if err := json.Unmarshal(captured.Body, &request); err != nil || request.PEM != string(pemBytes) {
		t.Fatalf("PEM import body was not the certificate JSON envelope: %v", err)
	}

	jsonBody := `{"pem":"public certificate","owner_id":"owner-1","source":"migration"}`
	code, _, stderr = run(t, []string{"certificates", "ingest", "-f", "-"}, env, jsonBody)
	if code != 0 || stderr != "" {
		t.Fatalf("JSON import = exit %d stderr=%q", code, stderr)
	}
	if !sameJSON(captured.Body, []byte(jsonBody)) {
		t.Fatalf("JSON import body changed: %s", captured.Body)
	}

	// A common fullchain file can contain more than one public certificate, but
	// accidentally appending a key must be refused before any HTTP request.
	captured = capture{}
	withKey := string(pemBytes) + string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("test-only-sentinel")}))
	code, _, stderr = run(t, []string{"certificates", "ingest", "-f", "-"}, env, withKey)
	if code == 0 || stderr == "" || captured.Method != "" {
		t.Fatalf("mixed certificate/key input = exit %d stderr=%q request_method=%q", code, stderr, captured.Method)
	}
}
