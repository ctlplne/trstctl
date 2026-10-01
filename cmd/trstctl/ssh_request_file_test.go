// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSSHAttestedRequestFileKeepsProofOutOfArguments(t *testing.T) {
	var received map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/ssh/attested-user-certs/preview" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Errorf("decode request: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ready":true,"effect_free":true}`))
	}))
	defer server.Close()

	path := filepath.Join(t.TempDir(), "attested-request.json")
	if err := os.WriteFile(path, []byte(`{"method":"k8s_sat","payload_base64":"cHJvb2Y=","public_key":"ssh-ed25519 AAAATEST"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	env := envFunc(map[string]string{
		"TRSTCTL_URL": server.URL, "TRSTCTL_TOKEN": "fixture-token",
		"TRSTCTL_TENANT": "11111111-1111-1111-1111-111111111111",
	})
	var stdout, stderr bytes.Buffer
	if err := run(context.Background(), []string{"ssh", "preview-attested-user", "-f", path}, env, &stdout, &stderr); err != nil {
		t.Fatalf("documented private request file failed: %v", err)
	}
	if received["payload_base64"] != "cHJvb2Y=" {
		t.Fatalf("file proof not sent: %+v", received)
	}
	if _, ok := received["approver"]; ok {
		t.Fatal("request file unexpectedly supplied an approver label")
	}
	if err := os.Chmod(path, 0o644); err != nil { // #nosec G302 -- deliberately public test fixture must be rejected by the private-file gate
		t.Fatal(err)
	}
	if err := run(context.Background(), []string{"ssh", "preview-attested-user", "-f", path}, env, &stdout, &stderr); err == nil || !strings.Contains(err.Error(), "private") {
		t.Fatalf("public proof file was accepted: %v", err)
	}
}
