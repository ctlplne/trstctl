// SPDX-License-Identifier: BUSL-1.1

//go:build e2e

package relay_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/agent/k8s"
	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/crypto/mtls"
)

// The dry-run of a k8s_secret target (K8S-O1) against a real Kubernetes API
// server: the kind cluster CI creates for test/e2e/kubernetes, with the same
// coordinates in the environment (K8S_SERVER, K8S_TOKEN, K8S_CA_FILE,
// K8S_ADMIN_TOKEN, K8S_NAMESPACE). The executor uses the agent's restricted
// service-account token, as it does in a pod; fixtures and verification use
// the admin token. Every request the executor sends is recorded, so "a dry-run
// reads and never writes" is checked on the wire, not taken on trust.

// kindAPICalls records the method and path of every request the executor
// sends to the API server.
type kindAPICalls struct {
	mu    sync.Mutex
	next  http.RoundTripper
	calls []string
}

func (c *kindAPICalls) RoundTrip(req *http.Request) (*http.Response, error) {
	c.mu.Lock()
	c.calls = append(c.calls, req.Method+" "+req.URL.Path)
	c.mu.Unlock()
	return c.next.RoundTrip(req)
}

func (c *kindAPICalls) take() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	calls := c.calls
	c.calls = nil
	return calls
}

type kindSecrets struct {
	namespace string
	// restricted is true when the executor's token is not the admin token,
	// so the cluster enforces the agent's RBAC.
	restricted bool
	calls      *kindAPICalls
	admin      func(method, path string, body any) (int, []byte)
}

// newKindSecrets points the k8s_secret executor at the live API server with
// the agent's token.
func newKindSecrets(t *testing.T) *kindSecrets {
	t.Helper()
	server, token, caFile := os.Getenv("K8S_SERVER"), os.Getenv("K8S_TOKEN"), os.Getenv("K8S_CA_FILE")
	if server == "" || token == "" || caFile == "" {
		t.Skip("K8S_SERVER, K8S_TOKEN and K8S_CA_FILE are not set; this proof needs a live cluster")
	}
	adminToken := os.Getenv("K8S_ADMIN_TOKEN")
	restricted := adminToken != "" && adminToken != token
	if adminToken == "" {
		adminToken = token // a local single-token run
	}
	namespace := os.Getenv("K8S_NAMESPACE")
	if namespace == "" {
		namespace = "default"
	}
	caPEM, err := os.ReadFile(caFile) // #nosec G304 G703 -- the cluster CA file the kind job exports (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	transport, err := mtls.HTTPTransport(caPEM)
	if err != nil {
		t.Fatal(err)
	}
	calls := &kindAPICalls{next: transport}
	agentClient := &http.Client{Transport: calls, Timeout: 30 * time.Second}
	t.Cleanup(relay.SetKubernetesClientForTest(func() (*k8s.Client, error) {
		return k8s.New(server, token, namespace, agentClient), nil
	}))
	adminClient := &http.Client{Transport: transport, Timeout: 30 * time.Second}
	admin := func(method, path string, body any) (int, []byte) {
		t.Helper()
		var reader io.Reader
		if body != nil {
			raw, err := json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
			reader = bytes.NewReader(raw)
		}
		req, err := http.NewRequestWithContext(context.Background(), method, server+path, reader) // #nosec G704 -- the kind cluster API server the job exports (CWE-918)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+adminToken)
		req.Header.Set("Accept", "application/json")
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := adminClient.Do(req) // #nosec G704 -- the kind cluster API server the job exports (CWE-918)
		if err != nil {
			t.Fatalf("%s %s: %v", method, path, err)
		}
		defer func() { _ = resp.Body.Close() }()
		data, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, data
	}
	return &kindSecrets{namespace: namespace, restricted: restricted, calls: calls, admin: admin}
}

func kindSecretName(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf("trstctl-dryrun-%d", time.Now().UnixNano())
}

func (k *kindSecrets) secretPath(namespace, name string) string {
	return "/api/v1/namespaces/" + namespace + "/secrets/" + name
}

func (k *kindSecrets) dryRun(t *testing.T, namespaces []string, namespace, name string) relay.Plan {
	t.Helper()
	plan, err := relay.DryRunOnHost(context.Background(), http.DefaultClient, clusterProfile(namespaces...), relay.DeployIntent{
		Connector: relay.KubernetesSecretConnector, Target: "web", TargetConfig: kubernetesSecretTarget(t, namespace, name),
	}, nil)
	if err != nil {
		t.Fatalf("DryRunOnHost: %v", err)
	}
	return plan
}

// readOnly fails unless every request the executor sent was a GET of the one
// Secret the target names.
func (k *kindSecrets) readOnly(t *testing.T, calls []string, namespace, name string) {
	t.Helper()
	if len(calls) == 0 {
		t.Fatal("the dry-run never asked the cluster about the Secret")
	}
	want := "GET " + k.secretPath(namespace, name)
	for _, call := range calls {
		if call != want {
			t.Fatalf("the dry-run sent %q to the cluster, want only %q: %v", call, want, calls)
		}
	}
}

func planStep(t *testing.T, plan relay.Plan, name string) relay.PlanStep {
	t.Helper()
	for _, step := range plan.Steps {
		if step.Name == name {
			return step
		}
	}
	t.Fatalf("the plan has no %q step: %+v", name, plan.Steps)
	return relay.PlanStep{}
}

func TestKubernetesSecretDryRunAgainstAClusterPlansACreateAndWritesNothing(t *testing.T) {
	cluster := newKindSecrets(t)
	name := kindSecretName(t)
	t.Cleanup(func() { cluster.admin(http.MethodDelete, cluster.secretPath(cluster.namespace, name), nil) })

	plan := cluster.dryRun(t, []string{cluster.namespace}, cluster.namespace, name)
	cluster.readOnly(t, cluster.calls.take(), cluster.namespace, name)
	if step := planStep(t, plan, "host-authority"); step.Status != relay.StepOK || !strings.Contains(step.Detail, "does not exist yet and a deploy would create it") {
		t.Fatalf("host-authority = %+v, want ok: the Secret does not exist yet and a deploy would create it", step)
	}
	if step := planStep(t, plan, "reachability"); step.Status != relay.StepSkipped {
		t.Fatalf("reachability = %+v, want skipped without a verify address", step)
	}
	want := fmt.Sprintf("replace tls.crt and tls.key in Secret %s/%s", cluster.namespace, name)
	if !plan.Ready || !slices.Equal(plan.WouldMutate, []string{want}) {
		t.Fatalf("plan = ready %v, would mutate %v; want ready, would mutate [%s]", plan.Ready, plan.WouldMutate, want)
	}
	if status, body := cluster.admin(http.MethodGet, cluster.secretPath(cluster.namespace, name), nil); status != http.StatusNotFound {
		t.Fatalf("after the dry-run the cluster answers %d for the Secret, want 404 (nothing written): %s", status, body)
	}
}

func TestKubernetesSecretDryRunAgainstAClusterPlansAReplaceAndLeavesTheSecretAsItWas(t *testing.T) {
	cluster := newKindSecrets(t)
	name := kindSecretName(t)
	encode := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
	status, body := cluster.admin(http.MethodPost, "/api/v1/namespaces/"+cluster.namespace+"/secrets", map[string]any{
		"apiVersion": "v1", "kind": "Secret", "type": "kubernetes.io/tls",
		"metadata": map[string]any{"name": name},
		"data":     map[string]string{"tls.crt": encode("THE SERVING CERTIFICATE"), "tls.key": encode("THE SERVING KEY")},
	})
	if status != http.StatusCreated {
		t.Fatalf("create the Secret fixture: %d %s", status, body)
	}
	t.Cleanup(func() { cluster.admin(http.MethodDelete, cluster.secretPath(cluster.namespace, name), nil) })
	before := secretState(t, body)

	plan := cluster.dryRun(t, []string{cluster.namespace}, cluster.namespace, name)
	cluster.readOnly(t, cluster.calls.take(), cluster.namespace, name)
	if step := planStep(t, plan, "host-authority"); step.Status != relay.StepOK || !strings.Contains(step.Detail, "exists and a deploy would replace its certificate and key") {
		t.Fatalf("host-authority = %+v, want ok: the Secret exists and a deploy would replace its certificate and key", step)
	}
	if !plan.Ready || len(plan.WouldMutate) != 1 {
		t.Fatalf("plan = ready %v, would mutate %v; want ready with one change named", plan.Ready, plan.WouldMutate)
	}
	status, body = cluster.admin(http.MethodGet, cluster.secretPath(cluster.namespace, name), nil)
	if status != http.StatusOK {
		t.Fatalf("read the Secret back: %d %s", status, body)
	}
	if after := secretState(t, body); after != before {
		t.Fatalf("the dry-run changed the Secret: before %+v, after %+v", before, after)
	}
}

func TestKubernetesSecretDryRunAgainstAClusterRefusesANamespaceOutsideTheProfile(t *testing.T) {
	cluster := newKindSecrets(t)
	plan := cluster.dryRun(t, []string{cluster.namespace}, "kube-system", kindSecretName(t))
	if calls := cluster.calls.take(); len(calls) != 0 {
		t.Fatalf("a target outside the profile reached the cluster: %v", calls)
	}
	step := planStep(t, plan, "target-config")
	if step.Status != relay.StepFailed || !strings.Contains(step.Detail, `does not allow writing Secrets in namespace "kube-system"`) {
		t.Fatalf("target-config = %+v, want failed naming the namespace the profile does not allow", step)
	}
	if plan.Ready || len(plan.WouldMutate) != 0 {
		t.Fatalf("plan = ready %v, would mutate %v; want not ready and nothing named", plan.Ready, plan.WouldMutate)
	}
}

// The operator's profile may list a namespace the agent's service account has
// no Secret rights in. The cluster refuses the read, and the dry-run says the
// deploy would fail there and why, before any key is generated for it.
func TestKubernetesSecretDryRunAgainstAClusterNamesTheAgentsRBAC(t *testing.T) {
	cluster := newKindSecrets(t)
	if !cluster.restricted {
		t.Skip("K8S_ADMIN_TOKEN is unset or equal to K8S_TOKEN: the executor's token is not restricted, so the cluster has no RBAC refusal to show")
	}
	const denied = "default"
	if cluster.namespace == denied {
		t.Fatalf("K8S_NAMESPACE is %q; the agent's Secret grant must be in another namespace for this proof", denied)
	}
	name := kindSecretName(t)
	plan := cluster.dryRun(t, []string{cluster.namespace, denied}, denied, name)
	cluster.readOnly(t, cluster.calls.take(), denied, name)
	step := planStep(t, plan, "host-authority")
	if step.Status != relay.StepFailed || !strings.Contains(step.Detail, "answered 403") ||
		!strings.Contains(step.Detail, "check this agent's RBAC for Secrets in "+denied) {
		t.Fatalf("host-authority = %+v, want failed: the cluster answered 403, check this agent's RBAC for Secrets in %s", step, denied)
	}
	if plan.Ready || len(plan.WouldMutate) != 0 {
		t.Fatalf("plan = ready %v, would mutate %v; want not ready and nothing named", plan.Ready, plan.WouldMutate)
	}
	if status, body := cluster.admin(http.MethodGet, cluster.secretPath(denied, name), nil); status != http.StatusNotFound {
		t.Fatalf("after the dry-run the cluster answers %d for %s/%s, want 404: %s", status, denied, name, body)
	}
}

type kindSecretState struct {
	UID, ResourceVersion, Cert, Key string
}

func secretState(t *testing.T, body []byte) kindSecretState {
	t.Helper()
	var obj struct {
		Metadata struct {
			UID             string `json:"uid"`
			ResourceVersion string `json:"resourceVersion"`
		} `json:"metadata"`
		Data map[string]string `json:"data"`
	}
	if err := json.Unmarshal(body, &obj); err != nil {
		t.Fatalf("decode the Secret: %v %s", err, body)
	}
	return kindSecretState{UID: obj.Metadata.UID, ResourceVersion: obj.Metadata.ResourceVersion, Cert: obj.Data["tls.crt"], Key: obj.Data["tls.key"]}
}
