// SPDX-License-Identifier: BUSL-1.1

package relay

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/connector"
)

func TestTomcatPreviewRequiresItsTLSActivationAction(t *testing.T) {
	listener := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	t.Cleanup(listener.Close)
	root := t.TempDir()
	certPath, keyPath := filepath.Join(root, "server.crt"), filepath.Join(root, "server.key")
	for _, path := range []string{certPath, keyPath} {
		if err := os.WriteFile(path, []byte("unchanged preview fixture"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	command, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	config, err := json.Marshal(HostTargetConfig{CertPath: certPath, KeyPath: keyPath})
	if err != nil {
		t.Fatal(err)
	}
	intent := DeployIntent{Connector: "tomcat", Target: "app", TargetID: "tomcat-target", TargetConfig: config, VerifyAddress: strings.TrimPrefix(listener.URL, "https://")}
	for _, tc := range []struct {
		name  string
		ready bool
	}{{"catalina.sh", false}, {"tomcat-tls-reload", true}} {
		t.Run(tc.name, func(t *testing.T) {
			profile := connector.LocalOpsConfig{AllowedRoots: []string{root}, Actions: []connector.LocalAction{{LogicalName: tc.name, Command: command, LogicalArgs: []string{}, PassArgs: false}}}
			plan, err := DryRunOnHost(t.Context(), http.DefaultClient, profile, intent, nil)
			if err != nil || plan.Ready != tc.ready {
				t.Fatalf("preview ready=%t, want %t; steps=%+v err=%v", plan.Ready, tc.ready, plan.Steps, err)
			}
		})
	}
	for _, path := range []string{certPath, keyPath} {
		body, err := os.ReadFile(path) // #nosec G304 -- fixed filenames below t.TempDir, no external input (CWE-22).
		if err != nil || string(body) != "unchanged preview fixture" {
			t.Fatal("preview changed the target files")
		}
	}
}
