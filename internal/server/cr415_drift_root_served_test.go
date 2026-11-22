// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/agent/drift"
	"trstctl.com/trstctl/internal/config"
)

func TestCR415ServedDriftRefusesTenantNamedHostFileWithoutOperatorRoot(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{}, func(*Deps) {})
	root := t.TempDir()
	path := filepath.Join(root, "private-pin-fixture")
	if err := os.WriteFile(path, []byte("123"), 0o600); err != nil {
		t.Fatal(err)
	}
	token := seedScopedToken(t, h.store, h.tenant, "discovery:read", "discovery:write")
	config := map[string]any{"watched": []map[string]any{{
		"path": path, "class": "certificate", "fingerprint": drift.Fingerprint([]byte("guess")),
	}}}
	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/discovery/sources", token,
		"cr415-no-root", map[string]any{"name": "cr415-unapproved-path", "kind": "drift", "config": config})
	if status != http.StatusBadRequest {
		t.Fatalf("unapproved drift source = HTTP %d %s, want 400 before storing host path", status, body)
	}
}

func TestCR415ServedDriftRunRechecksSymlinkAfterSourceCreation(t *testing.T) {
	parent := t.TempDir()
	approved := filepath.Join(parent, "approved")
	outside := filepath.Join(parent, "outside")
	for _, dir := range []string{approved, outside} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) { d.DriftRoots = []string{approved} })
	path := filepath.Join(approved, "leaf.pem")
	if err := os.WriteFile(path, []byte("declared"), 0o600); err != nil {
		t.Fatal(err)
	}
	token := seedScopedToken(t, h.store, h.tenant, "discovery:read", "discovery:write")
	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/discovery/sources", token,
		"cr415-approved-source", map[string]any{"name": "cr415-approved-source", "kind": "drift", "config": map[string]any{
			"watched": []map[string]any{{"path": path, "class": "certificate", "fingerprint": drift.Fingerprint([]byte("declared"))}},
		}})
	if status != http.StatusCreated {
		t.Fatalf("approved source = HTTP %d %s, want 201", status, body)
	}
	var source struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &source); err != nil || source.ID == "" {
		t.Fatalf("decode source: %v %s", err, body)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	canary := filepath.Join(outside, "canary")
	if err := os.WriteFile(canary, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(canary, path); err != nil {
		t.Fatal(err)
	}
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/discovery/runs", token,
		"cr415-swapped-run", map[string]any{"source_id": source.ID})
	if status != http.StatusCreated {
		t.Fatalf("queue swapped path = HTTP %d %s, want 201", status, body)
	}
	var queued struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &queued); err != nil || queued.ID == "" {
		t.Fatalf("decode queued run: %v %s", err, body)
	}
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatalf("drain refused drift run: %v", err)
	}
	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/discovery/runs/"+queued.ID, token, nil)
	if status != http.StatusOK || !strings.Contains(string(body), `"status":"failed"`) ||
		strings.Contains(string(body), canary) || strings.Contains(string(body), "outside") {
		t.Fatalf("swapped path run = HTTP %d %s, want failed without host detail", status, body)
	}
	findings := discoveryFindingsForRun(t, h, token, queued.ID)
	if len(findings.Items) != 0 {
		t.Fatalf("swapped path produced %d findings, want none", len(findings.Items))
	}
}
