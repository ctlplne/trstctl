// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/projections"
)

// A138: a TrustBundle rolled out through the served API to two clusters whose
// controllers report over the authenticated agent channel. Only the canary's
// controller is told to hold the bundle; once its own report shows the bundle
// distributed with the rollout's hash it is verified and the second cluster is
// told; the second cluster's report completes the rollout. An unknown cluster,
// a private key and an invalid transition are refused.
func TestServedKubernetesTrustRolloutVerifiesClustersFromTheirOwnReports(t *testing.T) {
	h := newServedHarness(t, config.Protocols{}, withAgentChannel)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	channelCtx, cancelChannel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); h.srv.serveAgentChannel(channelCtx, ln) }()
	t.Cleanup(func() { cancelChannel(); <-done })
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	clients := map[string]*transport.AgentClient{}
	canary, second := "sha256:"+strings.Repeat("a", 64), "sha256:"+strings.Repeat("b", 64)
	for cluster, name := range map[string]string{canary: "k8s-canary", second: "k8s-second"} {
		agent := enrollAgent(t, h, name, "agent.trstctl.local")
		creds, err := agent.Credentials()
		if err != nil {
			t.Fatal(err)
		}
		conn, err := transport.Dial(ln.Addr().String(), creds)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		clients[cluster] = transport.NewAgentClient(conn)
	}
	report := func(cluster string, bundles ...transport.KubernetesPostureResource) []transport.KubernetesDesiredTrustBundle {
		t.Helper()
		if bundles == nil {
			bundles = []transport.KubernetesPostureResource{}
		}
		receipt, err := clients[cluster].ReportKubernetesPosture(ctx, &transport.KubernetesPostureRequest{
			ReportID: uuid.NewString(), ClusterID: cluster, ReconcileIntervalSeconds: 30,
			CertificateSigning: transport.KubernetesPostureSection{Complete: true, Resources: []transport.KubernetesPostureResource{}},
			TrustBundles:       transport.KubernetesPostureSection{Complete: true, Resources: bundles},
		})
		if err != nil {
			t.Fatalf("posture report from %s: %v", cluster, err)
		}
		return receipt.DesiredTrustBundles
	}
	report(canary)
	report(second)

	tok := seedScopedToken(t, h.store, h.tenant, "certs:read", "certs:write")
	ca, err := mtls.NewCA("served rollout CA")
	if err != nil {
		t.Fatal(err)
	}
	request := map[string]any{
		"name": "platform-roots", "ca_bundle_pem": string(ca.BundlePEM()),
		"namespaces": []string{"apps", "payments"}, "clusters": []string{canary, second},
	}
	if st, body := secretsReq(t, h, http.MethodPost, "/api/v1/kubernetes/trust-rollouts", tok, map[string]any{
		"name": "platform-roots", "ca_bundle_pem": string(ca.BundlePEM()), "namespaces": []string{"apps"},
		"clusters": []string{"sha256:" + strings.Repeat("f", 64)},
	}); st != http.StatusUnprocessableEntity || !strings.Contains(string(body), "has not reported") {
		t.Fatalf("rollout to an unknown cluster = %d %s", st, body)
	}
	if st, body := secretsReq(t, h, http.MethodPost, "/api/v1/kubernetes/trust-rollouts", tok, map[string]any{
		"name": "platform-roots", "ca_bundle_pem": "-----BEGIN PRIVATE KEY-----\nS0VZ\n-----END PRIVATE KEY-----\n",
		"namespaces": []string{"apps"}, "clusters": []string{canary},
	}); st != http.StatusUnprocessableEntity {
		t.Fatalf("rollout of a private key = %d %s", st, body)
	}
	st, body := secretsReq(t, h, http.MethodPost, "/api/v1/kubernetes/trust-rollouts", tok, request)
	if st != http.StatusCreated {
		t.Fatalf("start rollout = %d %s", st, body)
	}
	var rollout api.KubernetesTrustRollout
	if err := json.Unmarshal(body, &rollout); err != nil {
		t.Fatal(err)
	}
	if rollout.State != "running" || len(rollout.Clusters) != 2 || !rollout.Clusters[0].Canary ||
		rollout.Clusters[0].State != "dispatched" || rollout.Clusters[1].State != "waiting" {
		t.Fatalf("started rollout = %+v", rollout)
	}
	if !h.hasEvent(t, projections.EventKubernetesTrustRolloutStarted) {
		t.Fatal("starting a rollout appended no event")
	}

	if got := report(second); len(got) != 0 {
		t.Fatalf("the waiting cluster was told to hold the bundle: %+v", got)
	}
	desired := report(canary)
	if len(desired) != 1 || desired[0].Name != "platform-roots" || desired[0].BundleSHA256 != rollout.BundleSHA256 ||
		desired[0].CABundlePEM != rollout.CABundlePEM || strings.Join(desired[0].Namespaces, ",") != "apps,payments" {
		t.Fatalf("the canary was told %+v", desired)
	}
	distributed := transport.KubernetesPostureResource{
		Name: "platform-roots", UID: "bundle-uid", ResourceVersion: "4", State: "ready", Reason: "distributed", PublicHash: rollout.BundleSHA256,
	}
	report(canary, distributed)
	get := func() api.KubernetesTrustRollout {
		t.Helper()
		st, body := secretsReq(t, h, http.MethodGet, "/api/v1/kubernetes/trust-rollouts/"+rollout.ID, tok, nil)
		if st != http.StatusOK {
			t.Fatalf("get rollout = %d %s", st, body)
		}
		var out api.KubernetesTrustRollout
		if err := json.Unmarshal(body, &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	if r := get(); r.Clusters[0].State != "verified" || r.Clusters[0].ReportID == "" || r.Clusters[1].State != "dispatched" || r.Verified != 1 {
		t.Fatalf("after the canary's own report = %+v", r)
	}
	if got := report(second); len(got) != 1 {
		t.Fatalf("the second cluster was not told after the canary verified: %+v", got)
	}

	if st, body := secretsReq(t, h, http.MethodPost, "/api/v1/kubernetes/trust-rollouts/"+rollout.ID+"/resume", tok, nil); st != http.StatusConflict {
		t.Fatalf("resume of a running rollout = %d %s", st, body)
	}
	if st, body := secretsReq(t, h, http.MethodPost, "/api/v1/kubernetes/trust-rollouts/"+rollout.ID+"/pause", tok, nil); st != http.StatusOK {
		t.Fatalf("pause = %d %s", st, body)
	}
	if st, body := secretsReq(t, h, http.MethodPost, "/api/v1/kubernetes/trust-rollouts/"+rollout.ID+"/resume", tok, nil); st != http.StatusOK {
		t.Fatalf("resume = %d %s", st, body)
	}
	report(second, distributed)
	if r := get(); r.State != "completed" || r.Verified != 2 {
		t.Fatalf("after both clusters reported = %+v", r)
	}
	st, body = secretsReq(t, h, http.MethodGet, "/api/v1/kubernetes/trust-rollouts", tok, nil)
	if st != http.StatusOK || !strings.Contains(string(body), rollout.ID) {
		t.Fatalf("list rollouts = %d %s", st, body)
	}
	reader := seedScopedToken(t, h.store, h.tenant, "certs:read")
	if st, _ := secretsReq(t, h, http.MethodPost, "/api/v1/kubernetes/trust-rollouts", reader, request); st != http.StatusForbidden {
		t.Fatalf("a read-only token started a rollout: %d", st)
	}
}
