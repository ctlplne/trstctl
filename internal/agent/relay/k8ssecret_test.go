// SPDX-License-Identifier: BUSL-1.1

package relay_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"trstctl.com/trstctl/internal/agent/k8s"
	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/custody"
)

// fakeKubeSecrets stands in for the Kubernetes Secrets API the in-cluster agent
// drives: GET/POST/PUT on /api/v1/namespaces/{ns}/secrets[/{name}].
type fakeKubeSecrets struct {
	mu      sync.Mutex
	secrets map[string]map[string]any // "ns/name" -> object
	writes  int
	// staleRead makes every GET answer with a different certificate, as a
	// cluster would if another writer replaced the Secret right after ours.
	staleRead bool
}

func newFakeKubeSecrets(t *testing.T) *fakeKubeSecrets {
	t.Helper()
	api := &fakeKubeSecrets{secrets: map[string]map[string]any{}}
	srv := httptest.NewServer(http.HandlerFunc(api.serve))
	t.Cleanup(srv.Close)
	t.Cleanup(relay.SetKubernetesClientForTest(func() (*k8s.Client, error) {
		return k8s.New(srv.URL, "cluster-agent-token", "trstctl", srv.Client()), nil
	}))
	return api
}

func (f *fakeKubeSecrets) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/") // api v1 namespaces {ns} secrets [name]
	if len(parts) < 5 {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	namespace := parts[3]
	switch r.Method {
	case http.MethodGet:
		obj, ok := f.secrets[namespace+"/"+parts[len(parts)-1]]
		if !ok {
			http.Error(w, `{"kind":"Status","code":404}`, http.StatusNotFound)
			return
		}
		if f.staleRead {
			stale := map[string]any{}
			for k, v := range obj {
				stale[k] = v
			}
			stale["data"] = map[string]any{"tls.crt": base64.StdEncoding.EncodeToString([]byte("ANOTHER WRITER'S CERTIFICATE"))}
			obj = stale
		}
		_ = json.NewEncoder(w).Encode(obj)
	case http.MethodPost, http.MethodPut:
		var obj map[string]any
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &obj); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		meta, _ := obj["metadata"].(map[string]any)
		name, _ := meta["name"].(string)
		meta["uid"] = "uid-" + name
		meta["resourceVersion"] = "1"
		f.secrets[namespace+"/"+name] = obj
		f.writes++
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(obj)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (f *fakeKubeSecrets) data(t *testing.T, namespace, name, key string) []byte {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	obj, ok := f.secrets[namespace+"/"+name]
	if !ok {
		t.Fatalf("secret %s/%s was not written", namespace, name)
	}
	if obj["type"] != "kubernetes.io/tls" {
		t.Fatalf("secret type = %v, want kubernetes.io/tls", obj["type"])
	}
	data, _ := obj["data"].(map[string]any)
	encoded, _ := data[key].(string)
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("data[%q] is not base64: %v", key, err)
	}
	return raw
}

func kubernetesSecretTarget(t *testing.T, namespace, name string) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(map[string]string{"namespace": namespace, "secret_name": name})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func clusterProfile(namespaces ...string) connector.LocalOpsConfig {
	return connector.LocalOpsConfig{KubernetesSecretNamespaces: namespaces}
}

// The in-cluster delivery writes the serving chain and the key into a
// kubernetes.io/tls Secret, then reads the Secret back and accepts the write
// only when the cluster holds the certificate it was given.
func TestKubernetesSecretInstallWritesTheServingChainAndReadsItBack(t *testing.T) {
	api := newFakeKubeSecrets(t)
	material := relay.Material{
		"credential.cert_pem":  []byte("LEAF\n"),
		"credential.chain_pem": []byte("ISSUER\n"),
		"credential.key_pem":   []byte("CLUSTER-GENERATED-KEY"),
	}
	if _, err := relay.ExecuteOnHost(context.Background(), clusterProfile("payments"), relay.DeployIntent{
		Connector: "k8s_secret", Target: "web", TargetConfig: kubernetesSecretTarget(t, "payments", "web-tls"),
	}, material); err != nil {
		t.Fatalf("ExecuteOnHost: %v", err)
	}
	if got := api.data(t, "payments", "web-tls", "tls.crt"); string(got) != "LEAF\nISSUER\n" {
		t.Fatalf("tls.crt = %q, want the leaf and its issuer", got)
	}
	if got := api.data(t, "payments", "web-tls", "tls.key"); string(got) != "CLUSTER-GENERATED-KEY" {
		t.Fatalf("tls.key = %q, want the key generated in the cluster", got)
	}
}

// The operator's profile is the boundary: a target naming a namespace the
// profile does not list is refused before anything is written.
func TestKubernetesSecretInstallRefusesANamespaceOutsideTheProfile(t *testing.T) {
	api := newFakeKubeSecrets(t)
	_, err := relay.ExecuteOnHost(context.Background(), clusterProfile("payments"), relay.DeployIntent{
		Connector: "k8s_secret", Target: "dns", TargetConfig: kubernetesSecretTarget(t, "kube-system", "dns-tls"),
	}, relay.Material{"credential.cert_pem": []byte("LEAF"), "credential.key_pem": []byte("KEY")})
	if err == nil || !strings.Contains(err.Error(), "kube-system") {
		t.Fatalf("ExecuteOnHost outside the profile = %v, want a refusal naming the namespace", err)
	}
	if api.writes != 0 {
		t.Fatalf("a refused target still wrote %d Secrets", api.writes)
	}
}

// An accepted write is not proof: when the Secret read back does not hold the
// certificate just written, the install fails rather than reporting success.
func TestKubernetesSecretInstallFailsWhenTheClusterHoldsAnotherCertificate(t *testing.T) {
	api := newFakeKubeSecrets(t)
	api.staleRead = true
	_, err := relay.ExecuteOnHost(context.Background(), clusterProfile("payments"), relay.DeployIntent{
		Connector: "k8s_secret", Target: "web", TargetConfig: kubernetesSecretTarget(t, "payments", "web-tls"),
	}, relay.Material{"credential.cert_pem": []byte("LEAF"), "credential.key_pem": []byte("KEY")})
	if err == nil || !strings.Contains(err.Error(), "does not hold") {
		t.Fatalf("ExecuteOnHost with a different certificate read back = %v, want a failed install", err)
	}
}

// A cluster agent's profile names the namespaces it may write Secrets in and
// no host files at all; a profile that permits nothing is still refused.
func TestHostProfileForAClusterAgentNamesNamespacesOnly(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	profile, err := relay.LoadHostProfile(write("cluster.json", `{"kubernetes_secrets":{"namespaces":["payments","web"]}}`))
	if err != nil {
		t.Fatalf("cluster profile refused: %v", err)
	}
	if strings.Join(profile.KubernetesSecretNamespaces, ",") != "payments,web" || len(profile.AllowedRoots) != 0 {
		t.Fatalf("cluster profile = %+v", profile)
	}
	if _, err := relay.LoadHostProfile(write("empty.json", `{}`)); err == nil {
		t.Fatal("a profile that permits nothing was accepted")
	}
	if _, err := relay.LoadHostProfile(write("bad.json", `{"kubernetes_secrets":{"namespaces":["Payments_Team"]}}`)); err == nil {
		t.Fatal("a namespace that is not a DNS label was accepted")
	}
}

// The whole renewal on a cluster agent: the key is generated in the agent, the
// CSR goes up, the issued chain and the key go into the Secret, and the custody
// the agent signs says the key is held by a Kubernetes Secret.
func TestKubernetesSecretRenewalWritesTheClusterGeneratedKey(t *testing.T) {
	api := newFakeKubeSecrets(t)
	ch := &renewChannel{certPEM: []byte("ISSUED-LEAF\n"), chainPEM: []byte("ISSUER\n"), fpr: "sha256:issued"}
	ch.jobs = []relay.Job{renewJob(t, relay.DeployIntent{
		Connector: "k8s_secret", Target: "web", TargetID: "target-web", SubjectCommonName: "web.example.test",
		SubjectDNSNames: []string{"web.example.test"}, TargetConfig: kubernetesSecretTarget(t, "payments", "web-tls"),
	})}
	if _, err := relay.RunOnceWithHost(t.Context(), ch, http.DefaultClient, clusterProfile("payments"), 1, 60); err != nil {
		t.Fatalf("RunOnceWithHost: %v", err)
	}
	if ch.signCalls != 1 || len(ch.signed) != 1 {
		t.Fatalf("signCalls = %d, want one CSR", ch.signCalls)
	}
	if got := api.data(t, "payments", "web-tls", "tls.crt"); string(got) != "ISSUED-LEAF\nISSUER\n" {
		t.Fatalf("tls.crt = %q", got)
	}
	key := api.data(t, "payments", "web-tls", "tls.key")
	if !bytes.Contains(key, []byte("PRIVATE KEY")) {
		t.Fatal("tls.key does not hold the key generated in the cluster")
	}
	if bytes.Contains(ch.signed[0], key) {
		t.Fatal("the CSR that left the agent carried the private key")
	}
	if len(ch.reports) != 1 || ch.reports[0].outcome != relay.OutcomeExecuted {
		t.Fatalf("reports = %+v, want one executed report (no verify address)", ch.reports)
	}
	if len(ch.custody) != 1 || ch.custody[0].Storage != custody.StorageKubernetesSecret ||
		ch.custody[0].Origin != custody.OriginHostAgent || ch.custody[0].Exportable != custody.Exportable {
		t.Fatalf("signed custody = %+v, want host_agent / kubernetes_secret / exportable", ch.custody)
	}
}

// Refused before a key exists: a target outside the profile's namespaces never
// reaches key generation or the signer.
func TestKubernetesSecretRenewalOutsideTheProfileRefusesBeforeGeneratingAKey(t *testing.T) {
	api := newFakeKubeSecrets(t)
	ch := &renewChannel{certPEM: []byte("ISSUED-LEAF\n"), fpr: "sha256:issued"}
	ch.jobs = []relay.Job{renewJob(t, relay.DeployIntent{
		Connector: "k8s_secret", Target: "dns", SubjectCommonName: "dns.example.test",
		TargetConfig: kubernetesSecretTarget(t, "kube-system", "dns-tls"),
	})}
	if _, err := relay.RunOnceWithHost(t.Context(), ch, http.DefaultClient, clusterProfile("payments"), 1, 60); err != nil {
		t.Fatalf("RunOnceWithHost: %v", err)
	}
	if ch.signCalls != 0 || api.writes != 0 {
		t.Fatalf("signCalls=%d writes=%d, want the target refused before any key or write", ch.signCalls, api.writes)
	}
	if len(ch.reports) != 1 || ch.reports[0].outcome != relay.OutcomeFailed || !strings.Contains(ch.reports[0].detail, "kube-system") {
		t.Fatalf("reports = %+v, want one failed report naming the namespace", ch.reports)
	}
}

// A cluster agent's profile grants host work without host roots: with its
// namespaces it asks for the whole claim set (renewals included) rather than
// the posture-only set of a host agent with no profile.
func TestClusterAgentProfileClaimsHostWork(t *testing.T) {
	store, err := relay.NewHostRollbackStore(filepath.Join(t.TempDir(), "rollbacks"), "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	if !relay.ProfileGrantsHostWork(clusterProfile("payments")) || relay.ProfileGrantsHostWork(connector.LocalOpsConfig{}) {
		t.Fatal("ProfileGrantsHostWork does not treat a namespace grant as host work")
	}
	cluster := &kindRecordingChannel{}
	if _, err := relay.RunOnceWithRoles(t.Context(), cluster, nil, clusterProfile("payments"), nil, nil, store,
		[]string{mtls.AgentRoleHost}, 4, 30); err != nil {
		t.Fatal(err)
	}
	if len(cluster.asked) != 1 || !slices.Equal(cluster.asked[0], relay.ClaimableKinds()) {
		t.Fatalf("cluster agent asked for %v; want the whole claim set %v", cluster.asked, relay.ClaimableKinds())
	}
}
