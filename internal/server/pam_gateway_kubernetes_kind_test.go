// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/mtls"
)

var fixtureKubectlCommand = regexp.MustCompile(`kubectl --kubeconfig (\S+) `)

// TestServedGatewayKubernetesSessionsOnKindA256: a Kubernetes target is
// served only through the access gateway, to stock kubectl with a
// kubeconfig that names the tunnel and no user. The gateway adds the
// session's TokenRequest token to every request, exec streams included;
// a client's own credential and impersonation are removed; the service
// account's role scopes the session; API calls and exec streams are recorded
// masked, sealed and verifiable; an operator's termination ends a live exec
// and the gateway acknowledges it; the session's service account is deleted.
// The runner names the cluster (K8S_SERVER, K8S_ADMIN_TOKEN, K8S_CA_FILE).
func TestServedGatewayKubernetesSessionsOnKindA256(t *testing.T) {
	server, adminToken, caFile := os.Getenv("K8S_SERVER"), os.Getenv("K8S_ADMIN_TOKEN"), os.Getenv("K8S_CA_FILE")
	if server == "" || adminToken == "" || caFile == "" {
		t.Skip("K8S_SERVER, K8S_ADMIN_TOKEN and K8S_CA_FILE name the cluster for this proof")
	}
	if _, err := exec.LookPath("kubectl"); err != nil {
		t.Skipf("the stock kubectl client is required: %v", err)
	}
	caPEM, err := os.ReadFile(caFile) // #nosec G304 G703 -- test reads the cluster CA its runner wrote (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	transport, err := mtls.HTTPTransport(caPEM)
	if err != nil {
		t.Fatal(err)
	}
	cluster := &http.Client{Transport: transport, Timeout: 30 * time.Second}
	kube := func(method, path string, body any) (int, []byte) {
		t.Helper()
		var reader io.Reader
		if body != nil {
			raw, err := json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
			reader = bytes.NewReader(raw)
		}
		req, err := http.NewRequestWithContext(context.Background(), method, server+path, reader) // #nosec G704 -- test calls the cluster its runner named (CWE-918)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+adminToken)
		req.Header.Set("Content-Type", "application/json")
		resp, err := cluster.Do(req) // #nosec G704 -- test calls the cluster its runner named (CWE-918)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		raw, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, raw
	}
	namespace := "trstctl-a256-" + strings.ToLower(time.Now().UTC().Format("150405"))
	if status, body := kube(http.MethodPost, "/api/v1/namespaces", map[string]any{"apiVersion": "v1", "kind": "Namespace",
		"metadata": map[string]any{"name": namespace}}); status != http.StatusCreated {
		t.Fatalf("create namespace: %d %s", status, body)
	}
	t.Cleanup(func() { kube(http.MethodDelete, "/api/v1/namespaces/"+namespace, nil) })
	if status, body := kube(http.MethodPost, "/api/v1/namespaces/"+namespace+"/pods", map[string]any{"apiVersion": "v1", "kind": "Pod",
		"metadata": map[string]any{"name": "shell"},
		"spec": map[string]any{"containers": []any{map[string]any{"name": "shell", "image": "registry.k8s.io/e2e-test-images/busybox:1.29-4",
			"imagePullPolicy": "Never", "command": []string{"sleep", "3600"}}}}}); status != http.StatusCreated {
		t.Fatalf("create pod: %d %s", status, body)
	}
	a201Await(t, "the shell pod", func() bool {
		_, body := kube(http.MethodGet, "/api/v1/namespaces/"+namespace+"/pods/shell", nil)
		return strings.Contains(string(body), `"phase":"Running"`)
	})
	_, body := kube(http.MethodGet, "/.well-known/openid-configuration", nil)
	var discovery struct{ Issuer string }
	if json.Unmarshal(body, &discovery) != nil || discovery.Issuer == "" {
		t.Fatalf("service-account issuer discovery: %s", body)
	}
	registry, err := dynamicSecretProvidersFromConfig(context.Background(), []config.DynamicSecretProviderConfig{{
		TenantID: servedTestTenant, ID: "pam-k8s-provider", Type: "kubernetes", Endpoint: server, Namespace: namespace,
		KubernetesAudience: discovery.Issuer, BearerTokenRef: writeServedCredentialFile(t, "k8s-admin-token", adminToken),
		KubernetesTLSCARef: writeServedCredentialFile(t, "k8s-ca.pem", string(caPEM)),
		AllowPrivate:       true, PrivateEgressCIDRs: []string{"127.0.0.0/8"},
		AllowedRoles: []string{"operator"}, RoleBindings: map[string]string{"operator": "ClusterRole/edit"}, MaxTTL: "1h",
		UsernamePrefix: "trstctl-a256",
	}}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	f := startGatewayFixture(t, gatewayFixtureOptions{kubernetes: registry, maxTTL: time.Hour})
	h := f.h
	serviceAccounts := func() []string {
		_, body := kube(http.MethodGet, "/api/v1/namespaces/"+namespace+"/serviceaccounts", nil)
		var list struct {
			Items []struct {
				Metadata struct{ Name string } `json:"metadata"`
			} `json:"items"`
		}
		_ = json.Unmarshal(body, &list)
		var names []string
		for _, item := range list.Items {
			if strings.HasPrefix(item.Metadata.Name, "trstctl-a256") {
				names = append(names, item.Metadata.Name)
			}
		}
		return names
	}

	session := f.open("a256-kubernetes", map[string]any{"target_type": "kubernetes", "target_id": "k8s-gw", "role": "operator", "ttl_seconds": 900})
	if session.Delivery != "gateway" || session.Gateway == nil {
		t.Fatalf("the Kubernetes session was not delivered through its gateway: %+v", session)
	}
	tunnelOut, stopTunnel := f.connect(session.ID, session.Gateway.Ticket, fixtureKubectlCommand.MatchString)
	defer stopTunnel()
	kubeconfig := fixtureKubectlCommand.FindStringSubmatch(tunnelOut)[1]
	accounts := serviceAccounts()
	if len(accounts) != 1 {
		t.Fatalf("session service accounts = %v, want the session's one", accounts)
	}
	raw, err := os.ReadFile(kubeconfig) // #nosec G304 G703 -- the kubeconfig the CLI wrote for this test (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	for what, text := range map[string]string{"kubeconfig": string(raw), "CLI output": tunnelOut} {
		if strings.Contains(text, "token") || strings.Contains(text, "eyJ") {
			t.Fatalf("the %s carries a credential: %s", what, text)
		}
	}
	kubectl := func(stdin string, args ...string) string {
		cmd := exec.CommandContext(f.ctx, "kubectl", append([]string{"--kubeconfig", kubeconfig, "-n", namespace}, args...)...) // #nosec G204 G702 -- the stock kubectl against the test's own tunnel (CWE-78)
		cmd.Stdin = strings.NewReader(stdin)
		out, _ := cmd.CombinedOutput()
		return strings.TrimSpace(string(out))
	}
	if got := kubectl("", "get", "pods", "-o", "name"); got != "pod/shell" {
		t.Fatalf("kubectl get pods through the gateway = %q (gateway: %s)", got, f.gatewayLog.String())
	}
	subject := "system:serviceaccount:" + namespace + ":" + accounts[0]
	if got := kubectl("", "get", "nodes"); !strings.Contains(got, "Forbidden") || !strings.Contains(got, subject) {
		t.Fatalf("a cluster-scoped read outside the session's role = %q", got)
	}
	// A client's impersonation is removed: the request is still the
	// session's service account, not a refused impersonation.
	if got := kubectl("", "--as=system:admin", "get", "nodes"); !strings.Contains(got, subject) || strings.Contains(got, "impersonate") {
		t.Fatalf("an impersonating request = %q", got)
	}
	token := "ghp_a256KubernetesSessionTk" + strings.Repeat("K", 13) // a GitHub token's shape: ghp_ and 36 characters
	if got := kubectl("", "exec", "shell", "--", "sh", "-c", "echo printed=$0", token); got != "printed="+token {
		t.Fatalf("kubectl exec through the gateway = %q", got)
	}

	// A live exec, terminated.
	live := exec.CommandContext(f.ctx, "kubectl", "--kubeconfig", kubeconfig, "-n", namespace, "exec", "-i", "shell", "--", "sh", "-c", "while read line; do echo got $line; done") // #nosec G204 G702 -- the stock kubectl against the test's own tunnel (CWE-78)
	shell := startLiveShell(t, live)
	shell.echo("before")
	if status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/sessions/"+session.ID+"/terminate", f.operator,
		"a256-k8s-terminate", map[string]any{"reason": "a256 proof"}); status != http.StatusAccepted {
		t.Fatalf("terminate = %d %s", status, body)
	}
	if !shell.ended(30 * time.Second) {
		t.Fatal("the terminated exec is still running")
	}
	a201Await(t, "the gateway acknowledges the termination", func() bool {
		end, _ := f.sessionRead(session.ID)["gateway_end"].(map[string]any)
		return end != nil && end["ended"] == "recalled"
	})
	a201Await(t, "the session's service account is deleted", func() bool { return len(serviceAccounts()) == 0 })

	// The recording.
	a201Await(t, "the Kubernetes recording seals", func() bool {
		status, body := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/access/sessions/"+session.ID+"/recording", f.requester, nil)
		return status == http.StatusOK && strings.Contains(string(body), `"status":"sealed"`)
	})
	if status, body := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/access/sessions/"+session.ID+"/recording/verify", f.requester, nil); status != http.StatusOK || !strings.Contains(string(body), `"verified":true`) {
		t.Fatalf("verify = %d %s", status, body)
	}
	text := recordingText(t, h, session.ID)
	if strings.Contains(text, token) || strings.Contains(text, adminToken) {
		t.Fatalf("the Kubernetes recording kept a secret:\n%s", text)
	}
	for _, want := range []string{"request: GET /api/v1/namespaces/" + namespace + "/pods", "request: GET /api/v1/nodes", "response: 403",
		"stream websocket", "printed=[masked:github-token]", "got before"} {
		if !strings.Contains(text, want) {
			t.Fatalf("the Kubernetes recording lacks %q:\n%s", want, text)
		}
	}
}
