// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/secret"
)

// Q6-O2 lab: a kind cluster (kindest/node, Kubernetes 1.35) whose API server
// sends its audit events to the served control plane through the audit
// webhook, with a token that holds only decoys:events.report. The decoy is
// registered through the API and planted with the manifest it returns;
// `kubectl get secret` of its token Secret raises the decoy alert naming
// kubernetes-admin, and kubectl using the token raises one naming the client.
// Run by runners/q6o2-kind-lab-proof.sh; the test creates and deletes its own
// cluster.
func TestServedKubernetesDecoyOnKindQ6O2(t *testing.T) {
	image := os.Getenv("TRSTCTL_Q6O2_KIND_IMAGE")
	if image == "" {
		t.Skip("run runners/q6o2-kind-lab-proof.sh (kind and a local kindest/node image)")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	h := newServedHarness(t, config.Protocols{})
	registerServedTenant(t, h, "q6o2-kind")
	operator := seedServedAPIToken(t, ctx, h.store, h.tenant, "decoy-planter", []string{"secrets:write"})
	webhook := seedServedAPIToken(t, ctx, h.store, h.tenant, "system:apiserver-audit", []string{"decoys:events.report"})
	const cluster, clusterName = "q6o2-kind", "trstctl-build-q6o2"

	code, body := doBearer(t, h.ts, http.MethodPost, "/api/v1/secrets/honeytokens/kubernetes", operator, "q6o2-kind-register",
		map[string]any{"cluster": cluster, "namespace": "ci", "service_account": "ci-deployer", "name": "ci deployer token", "placement": "ci namespace"})
	if code != http.StatusCreated {
		t.Fatalf("register: %d %s", code, body)
	}
	var registered struct {
		ID          string `json:"id"`
		Manifest    string `json:"manifest"`
		AuditPolicy string `json:"audit_policy"`
	}
	if err := json.Unmarshal(body, &registered); err != nil {
		t.Fatal(err)
	}

	work := t.TempDir()
	audit := filepath.Join(work, "audit")
	if err := os.MkdirAll(audit, 0o755); err != nil { // #nosec G301 -- the kind node reads the lab's audit configuration
		t.Fatal(err)
	}
	write := func(path, body string, mode os.FileMode) {
		t.Helper()
		if err := os.WriteFile(path, []byte(body), mode); err != nil { // #nosec G306 G703 -- disposable lab configuration the kind node reads (CWE-22)
			t.Fatal(err)
		}
	}
	// The registration's rules, then nothing else: the cluster's own policy
	// would keep its rules after these.
	rules := strings.Join(strings.Split(strings.TrimSpace(registered.AuditPolicy), "\n")[1:], "\n")
	write(filepath.Join(audit, "policy.yaml"), "apiVersion: audit.k8s.io/v1\nkind: Policy\nomitStages: [\"RequestReceived\"]\nrules:\n"+rules+"\n- level: None\n", 0o644)
	// The API server reaches the served control plane through a TLS
	// pass-through that keeps what it sent: the path, whether a bearer came
	// with it, and what the control plane answered. TLS is not optional: the
	// API server's kubeconfig loader sends a token only to an https server.
	target, err := url.Parse(h.ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	var seenMu sync.Mutex
	var seen []string
	proxy := httputil.NewSingleHostReverseProxy(target)
	front := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		proxy.ServeHTTP(rec, r)
		seenMu.Lock()
		seen = append(seen, fmt.Sprintf("%s %s bearer=%t -> %d", r.Method, r.URL.Path, strings.HasPrefix(r.Header.Get("Authorization"), "Bearer trst_"), rec.status))
		seenMu.Unlock()
	}))
	front.StartTLS()
	defer front.Close()
	frontCA := base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: front.Certificate().Raw}))
	t.Cleanup(func() {
		seenMu.Lock()
		defer seenMu.Unlock()
		t.Logf("the API server's webhook requests: %v", seen)
	})
	port := front.URL[strings.LastIndex(front.URL, ":")+1:]
	write(filepath.Join(audit, "webhook.kubeconfig"), `apiVersion: v1
kind: Config
clusters:
- name: trstctl
  cluster:
    server: https://host.docker.internal:`+port+`/api/v1/secrets/honeytokens/kubernetes/clusters/`+cluster+`/audit-events
    certificate-authority-data: `+frontCA+`
    tls-server-name: example.com
users:
- name: audit
  user:
    token: `+webhook+`
contexts:
- name: default
  context:
    cluster: trstctl
    user: audit
current-context: default
`, 0o644)
	write(filepath.Join(work, "kind.yaml"), `kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
  extraMounts:
  - hostPath: `+audit+`
    containerPath: /etc/kubernetes/audit
    readOnly: true
  kubeadmConfigPatches:
  - |
    kind: ClusterConfiguration
    apiServer:
      extraArgs:
        audit-policy-file: /etc/kubernetes/audit/policy.yaml
        audit-webhook-config-file: /etc/kubernetes/audit/webhook.kubeconfig
        audit-webhook-batch-max-wait: 1s
      extraVolumes:
      - name: audit
        hostPath: /etc/kubernetes/audit
        mountPath: /etc/kubernetes/audit
        readOnly: true
        pathType: Directory
`, 0o644)
	run := func(stdin string, name string, args ...string) (string, error) {
		cmd := exec.CommandContext(ctx, name, args...) // #nosec G204 G702 -- kind and kubectl with the lab's own arguments (CWE-78)
		var out bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &out
		if stdin != "" {
			cmd.Stdin = strings.NewReader(stdin)
		}
		err := cmd.Run()
		return out.String(), err
	}
	_, _ = run("", "kind", "delete", "cluster", "--name", clusterName)
	t.Cleanup(func() { _ = exec.Command("kind", "delete", "cluster", "--name", clusterName).Run() }) // #nosec G204 -- the lab's own cluster (CWE-78)
	admin := filepath.Join(work, "admin.kubeconfig")
	if out, err := run("", "kind", "create", "cluster", "--name", clusterName, "--image", image, "--config", filepath.Join(work, "kind.yaml"),
		"--kubeconfig", admin, "--wait", "180s"); err != nil {
		t.Fatalf("create the kind cluster: %v\n%s", err, out)
	}
	kubectl := func(stdin string, args ...string) string {
		t.Helper()
		out, err := run(stdin, "kubectl", append([]string{"--kubeconfig", admin}, args...)...)
		if err != nil {
			t.Fatalf("kubectl %s: %v\n%s", strings.Join(args, " "), err, out)
		}
		return out
	}
	kubectl("", "create", "namespace", "ci")
	kubectl(registered.Manifest, "apply", "-f", "-")

	alerts := func() []string {
		t.Helper()
		rows, err := h.store.SystemPool().Query(ctx,
			`SELECT convert_from(payload, 'UTF8')::jsonb->>'detail' FROM outbox
			  WHERE tenant_id = $1 AND destination = 'notification.honeytoken' ORDER BY id`, h.tenant)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var out []string
		for rows.Next() {
			var d string
			if err := rows.Scan(&d); err != nil {
				t.Fatal(err)
			}
			out = append(out, d)
		}
		return out
	}
	waitAlerts := func(n int, what string) []string {
		t.Helper()
		deadline := time.Now().Add(90 * time.Second)
		for {
			got := alerts()
			if len(got) >= n {
				return got
			}
			if time.Now().After(deadline) {
				logs, _ := run("", "kubectl", "--kubeconfig", admin, "-n", "kube-system", "logs", "kube-apiserver-"+clusterName+"-control-plane", "--tail", "40")
				t.Fatalf("%s: %d alerts, want %d: %v\nAPI server log:\n%s", what, len(got), n, got, logs)
			}
			time.Sleep(time.Second)
		}
	}
	if got := alerts(); len(got) != 0 {
		t.Fatalf("planting the decoy raised alerts: %v", got)
	}

	// The token controller fills the Secret; that write is not a read.
	var token []byte
	deadline := time.Now().Add(60 * time.Second)
	for len(token) == 0 {
		encoded, _ := run("", "kubectl", "--kubeconfig", admin, "-n", "ci", "get", "secret", "ci-deployer-token", "-o", "jsonpath={.data.token}")
		if decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded)); err == nil && len(decoded) > 0 {
			token = decoded
		}
		if time.Now().After(deadline) {
			t.Fatal("the token controller never filled the decoy's Secret")
		}
		time.Sleep(time.Second)
	}
	defer secret.Wipe(token)
	read := waitAlerts(1, "the read of the decoy's Secret")
	if !strings.Contains(read[0], "ci/ci-deployer on cluster "+cluster) || !strings.Contains(read[0], "token Secret read: get secrets (200)") ||
		!strings.Contains(read[0], "by kubernetes-admin from ") {
		t.Fatalf("the read alert %q does not name the decoy, the read and kubernetes-admin", read[0])
	}
	t.Logf("read alert: %s", read[0])

	// Somebody uses the token: it authorizes nothing.
	server := strings.TrimSpace(kubectl("", "config", "view", "--minify", "-o", "jsonpath={.clusters[0].cluster.server}"))
	ca := strings.TrimSpace(kubectl("", "config", "view", "--minify", "--raw", "-o", "jsonpath={.clusters[0].cluster.certificate-authority-data}"))
	thief := filepath.Join(work, "thief.kubeconfig")
	write(thief, `apiVersion: v1
kind: Config
clusters:
- name: kind
  cluster:
    server: `+server+`
    certificate-authority-data: `+ca+`
users:
- name: thief
  user:
    token: `+string(token)+`
contexts:
- name: default
  context:
    cluster: kind
    user: thief
current-context: default
`, 0o600)
	out, err := run("", "kubectl", "--kubeconfig", thief, "-n", "ci", "get", "pods")
	if err == nil || !strings.Contains(out, "forbidden") {
		t.Fatalf("the decoy token did something: %v\n%s", err, out)
	}
	if err := os.Remove(thief); err != nil {
		t.Fatal(err)
	}
	used := waitAlerts(2, "the use of the decoy's token")
	if !strings.Contains(used[1], "token used: list pods (403)") || !strings.Contains(used[1], "by kubectl/") {
		t.Fatalf("the use alert %q does not name the use and the kubectl client", used[1])
	}
	t.Logf("use alert: %s", used[1])
	seenMu.Lock()
	answered := strings.Join(seen, "\n")
	seenMu.Unlock()
	if !strings.Contains(answered, "bearer=true -> 200") || strings.Contains(answered, "bearer=false") {
		t.Fatalf("the API server's webhook requests:\n%s\nwant each with its bearer, answered 200", answered)
	}
	decoy, err := h.store.GetHoneyToken(ctx, h.tenant, registered.ID)
	if err != nil || decoy.State != "triggered" || !strings.HasPrefix(decoy.TriggerSubject, "kubernetes-admin from ") || decoy.Readers != 2 {
		t.Fatalf("decoy = %+v, %v", decoy, err)
	}
}

// statusRecorder keeps the status a handler wrote.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}
