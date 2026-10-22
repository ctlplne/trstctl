// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// B7: the executor census carries the reason the host exec profile could not
// be loaded, so the control plane can refuse host work bound to this agent by
// name instead of queuing rows it will never claim.
func TestExecutorCensusReportsAnUnloadableHostProfile(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "openssl-real")
	if err := os.WriteFile(real, []byte("#!/bin/sh\n"), 0o755); err != nil { // #nosec G306 -- fixture executable written by this test (CWE-276)
		t.Fatal(err)
	}
	link := filepath.Join(dir, "openssl")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	write := func(name string, profile map[string]any) string {
		t.Helper()
		raw, _ := json.Marshal(profile)
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	broken := write("broken.json", map[string]any{"allowed_roots": []string{dir}, "tls_probe_openssl": link})
	report := executorCensus(agentOptions{relayClaim: true, hostExecProfile: broken})
	if report.HostTLSProbe || !strings.Contains(report.HostProfileError, "symbolic link to") || !strings.Contains(report.HostProfileError, "openssl-real") {
		t.Fatalf("census for a symlinked probe = probe %v error %q, want the resolved path named", report.HostTLSProbe, report.HostProfileError)
	}

	loaded := write("loaded.json", map[string]any{"allowed_roots": []string{dir}, "tls_probe_openssl": real})
	report = executorCensus(agentOptions{relayClaim: true, hostExecProfile: loaded})
	if !report.HostTLSProbe || report.HostProfileError != "" {
		t.Fatalf("census for a loadable profile = probe %v error %q", report.HostTLSProbe, report.HostProfileError)
	}
	if report = executorCensus(agentOptions{relayClaim: true}); report.HostTLSProbe || report.HostProfileError != "" {
		t.Fatalf("census without a profile = probe %v error %q", report.HostTLSProbe, report.HostProfileError)
	}
}
