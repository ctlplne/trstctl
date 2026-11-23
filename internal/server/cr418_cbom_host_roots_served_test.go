// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"trstctl.com/trstctl/internal/config"
)

func TestCR418ServedCBOMRefusesControlPlaneHostFilesWithoutOperatorRoots(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private.conf")
	if err := os.WriteFile(path, []byte("ssl_protocols TLSv1.0;\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	h := newOperatingServedHarness(t, config.Protocols{})
	token := seedScopedToken(t, h.store, h.tenant, "discovery:write", "risk:read")
	request := map[string]any{"host_configs": []string{path}}
	if status, body := secretsReq(t, h, http.MethodPost, "/api/v1/cbom/scans/preview", token, request); status != http.StatusBadRequest {
		t.Fatalf("unapproved host path preview status=%d body=%s", status, body)
	}
	if status, body := secretsReq(t, h, http.MethodPost, "/api/v1/cbom/scans", token, request); status != http.StatusBadRequest {
		t.Fatalf("unapproved host path scan status=%d body=%s", status, body)
	}
}

func TestCR418ServedCBOMReplayDoesNotReopenRemovedHostFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tls.conf")
	if err := os.WriteFile(path, []byte("ssl_protocols TLSv1.2;\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) { d.CBOMHostRoots = []string{dir} })
	token := seedScopedToken(t, h.store, h.tenant, "discovery:write", "risk:read")
	request := map[string]any{"host_configs": []string{path}}
	firstStatus, firstBody := secretsReqKey(t, h, http.MethodPost, "/api/v1/cbom/scans", token, "cr418-replay", request)
	if firstStatus != http.StatusCreated || !bytes.Contains(firstBody, []byte(`"findings":1`)) {
		t.Fatalf("first host scan status=%d body=%s", firstStatus, firstBody)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	replayStatus, replayBody := secretsReqKey(t, h, http.MethodPost, "/api/v1/cbom/scans", token, "cr418-replay", request)
	if replayStatus != firstStatus || !bytes.Equal(replayBody, firstBody) {
		t.Fatalf("replay after removal status=%d body=%s; want original %d %s", replayStatus, replayBody, firstStatus, firstBody)
	}
}
