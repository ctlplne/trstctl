// SPDX-License-Identifier: BUSL-1.1

package cli

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCR037KubeconfigReplacesPublicSymlinkWithPrivateCapabilityPath(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "old-public-file")
	if err := os.WriteFile(target, []byte("do not overwrite"), 0o644); err != nil { // #nosec G306 -- intentionally public old file proves the new kubeconfig is replaced with private mode (CWE-732)
		t.Fatal(err)
	}
	path := filepath.Join(dir, "session.kubeconfig")
	if err := os.Symlink(target, path); err != nil {
		t.Skipf("symlinks unavailable on this host: %v", err)
	}
	capability := strings.Repeat("c", 64)
	var cleanup []string
	line, err := gatewayClientLine("kubernetes", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 18080}, "", "", path, gatewayDelivery{localCapability: capability, localArtifacts: &cleanup})
	if err != nil || !strings.Contains(line, "--kubeconfig "+path) {
		t.Fatalf("kubectl local command = %q, %v", line, err)
	}
	if len(cleanup) != 1 || cleanup[0] != path {
		t.Fatalf("private kubeconfig was not registered for connect-exit cleanup: %v", cleanup)
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("kubeconfig did not replace the symlink with mode 0600: %v, %v", info, err)
	}
	config, err := os.ReadFile(path) // #nosec G304 -- reads the kubeconfig created in this test's private temporary directory (CWE-22)
	if err != nil || !strings.Contains(string(config), "server: http://127.0.0.1:18080/.trstctl/"+capability) || strings.Contains(string(config), "token:") {
		t.Fatalf("kubeconfig lacks the local path capability or carries a bearer: %v", err)
	}
	old, err := os.ReadFile(target) // #nosec G304 -- reads this test's fixed symlink target in its private temporary directory (CWE-22)
	if err != nil || string(old) != "do not overwrite" {
		t.Fatalf("symlink target was overwritten: %q, %v", old, err)
	}
}

func TestCR037StockKubectlSendsTheLocalCapabilityPath(t *testing.T) {
	if _, err := exec.LookPath("kubectl"); err != nil {
		t.Skipf("stock kubectl unavailable: %v", err)
	}
	capability := strings.Repeat("e", 64)
	seen := make(chan string, 16)
	prefix := "/.trstctl/" + capability
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case seen <- r.URL.Path:
		default:
		}
		w.Header().Set("Content-Type", "application/json")
		switch strings.TrimPrefix(r.URL.Path, prefix) {
		case "/api":
			_, _ = io.WriteString(w, `{"kind":"APIVersions","versions":["v1"],"serverAddressByClientCIDRs":[]}`)
		case "/apis":
			_, _ = io.WriteString(w, `{"kind":"APIGroupList","groups":[]}`)
		case "/api/v1":
			_, _ = io.WriteString(w, `{"kind":"APIResourceList","groupVersion":"v1","resources":[{"name":"pods","singularName":"","namespaced":true,"kind":"Pod","verbs":["get","list","watch"]}]}`)
		case "/api/v1/namespaces/default/pods":
			_, _ = io.WriteString(w, `{"kind":"PodList","apiVersion":"v1","metadata":{"resourceVersion":"1"},"items":[]}`)
		default:
			http.Error(w, "unknown Kubernetes API path", http.StatusNotFound)
		}
	}))
	defer server.Close()
	path := filepath.Join(t.TempDir(), "session.kubeconfig")
	local := server.Listener.Addr().(*net.TCPAddr)
	if _, err := gatewayClientLine("kubernetes", local, "", "", path, gatewayDelivery{localCapability: capability}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "kubectl", "--kubeconfig", path, "--cache-dir", t.TempDir(), "get", "pods").CombinedOutput() // #nosec G204 -- fixed stock-client command and this test's private kubeconfig (CWE-78)
	if err != nil {
		t.Fatalf("stock kubectl did not reach the local tunnel: %v %s", err, out)
	}
	if len(seen) == 0 {
		t.Fatal("stock kubectl did not send a request")
	}
	for len(seen) > 0 {
		got := <-seen
		if !strings.HasPrefix(got, prefix+"/") {
			t.Fatalf("stock kubectl request omitted the capability path: %q", got)
		}
	}
}

func TestCR037WebConsoleCommandBootstrapsOnlyItsLocalCapability(t *testing.T) {
	capability := strings.Repeat("d", 64)
	line, err := gatewayClientLine("webconsole", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 18080}, "", "", "", gatewayDelivery{localCapability: capability})
	if err != nil || !strings.Contains(line, "http://127.0.0.1:18080/?trstctl_tunnel="+capability) {
		t.Fatalf("web console bootstrap link = %q, %v", line, err)
	}
	if _, err := gatewayClientLine("webconsole", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 18080}, "", "", ""); err == nil {
		t.Fatal("web console link was printed without a local capability")
	}
}
