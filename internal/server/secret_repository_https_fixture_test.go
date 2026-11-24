// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/pem"
	"net/http/cgi" // #nosec G504 -- test-only local Git smart-HTTPS fixture (CWE-284)
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// serveTestGitHTTPS exposes a test-owned repository through Git's real smart
// HTTP backend. The served clone path therefore exercises HTTPS pinning and
// the hook's exact private-network grant, not a local-file shortcut.
func serveTestGitHTTPS(t *testing.T, source string) string {
	t.Helper()
	execPath, err := exec.Command("git", "--exec-path").Output() // #nosec G204 -- fixed local Git tool (CWE-78)
	if err != nil {
		t.Skipf("git is unavailable: %v", err)
	}
	backend := filepath.Join(strings.TrimSpace(string(execPath)), "git-http-backend")
	if _, err := os.Stat(backend); err != nil {
		t.Skipf("git-http-backend is unavailable: %v", err)
	}
	hosted := t.TempDir()
	cmd := exec.Command("git", "clone", "-q", "--bare", source, filepath.Join(hosted, "payments.git")) // #nosec G204 -- source and target are test-owned repositories (CWE-78)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("prepare smart-HTTPS repository: %v %s", err, out)
	}
	server := httptest.NewTLSServer(&cgi.Handler{Path: backend, Env: []string{
		"GIT_PROJECT_ROOT=" + hosted, "GIT_HTTP_EXPORT_ALL=1",
	}})
	t.Cleanup(server.Close)
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GIT_SSL_CAINFO", ca)
	return server.URL + "/payments.git"
}
