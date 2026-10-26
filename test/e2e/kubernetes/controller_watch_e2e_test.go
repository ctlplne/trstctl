// SPDX-License-Identifier: BUSL-1.1

//go:build e2e

package kubernetes_e2e

import (
	"context"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/agent/k8s"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/mtls"
)

// TestIssuerControllerRunsFromWatchEvents runs the agent's Kubernetes
// controller event-driven against a real API server with the agent's own
// least-privilege service account, and a resync and heartbeat ten minutes
// away, so everything it does within seconds came from a watch: a TrustBundle
// reaches its namespace and a deleted copy is put back, an approved native CSR
// is signed, and a trstctl Certificate is issued into its Secret and renewed
// before it expires.
func TestIssuerControllerRunsFromWatchEvents(t *testing.T) {
	requireIndependentApprover(t)
	client, _, ns := cluster(t)
	k := newKubeAPI(t)
	applyCRDFile(k, filepath.Join("..", "..", "..", "deploy", "kubernetes", "certmanager-issuer-crds.yaml"))

	ca, err := mtls.NewCA("trstctl watch e2e issuer")
	if err != nil {
		t.Fatal(err)
	}
	signerURL := "https://trstctl.trstctl.svc/api/v1/ca/authorities/e2e/issue"
	controller, err := k8s.NewIssuerController(client, k8s.SignerFunc(func(_ context.Context, csrDER []byte, ttl time.Duration) ([]byte, error) {
		return ca.SignClientCSR(csrDER, ttl)
	}), "trstctl.com", signerURL)
	if err != nil {
		t.Fatal(err)
	}

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	clusterIssuers := "/apis/trstctl.com/v1alpha1/clusterissuers/"
	// The agent may sign native CSRs only for trstctl.com/trstctl (rbac.yaml).
	if st, _ := k.do(http.MethodGet, clusterIssuers+"trstctl", "", nil); st == http.StatusNotFound {
		k.must(http.MethodPost, "/apis/trstctl.com/v1alpha1/clusterissuers", "", map[string]any{
			"apiVersion": "trstctl.com/v1alpha1", "kind": "ClusterIssuer",
			"metadata": map[string]any{"name": "trstctl"}, "spec": map[string]any{"signerURL": signerURL},
		})
		t.Cleanup(func() { k.do(http.MethodDelete, clusterIssuers+"trstctl", "", nil) })
	}
	short := "trstctl-watch-" + suffix
	k.must(http.MethodPost, "/apis/trstctl.com/v1alpha1/clusterissuers", "", map[string]any{
		"apiVersion": "trstctl.com/v1alpha1", "kind": "ClusterIssuer",
		"metadata": map[string]any{"name": short}, "spec": map[string]any{"signerURL": signerURL, "ttlSeconds": 8},
	})
	t.Cleanup(func() { k.do(http.MethodDelete, clusterIssuers+short, "", nil) })

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- controller.Run(ctx, k8s.RunOptions{ClusterID: client.ClusterID(), ReportEvery: 10 * time.Minute, Resync: 10 * time.Minute})
	}()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Run: %v", err)
		}
	})
	waitFor := func(what string, within time.Duration, cond func() bool) {
		t.Helper()
		start := time.Now()
		for !cond() {
			if time.Since(start) > within {
				t.Fatalf("not within %s: %s", within, what)
			}
			time.Sleep(100 * time.Millisecond)
		}
		t.Logf("%s after %s", what, time.Since(start).Round(10*time.Millisecond))
	}

	// TrustBundle.
	bundleName := "trstctl-watch-" + suffix
	configMapPath := "/api/v1/namespaces/" + ns + "/configmaps/" + bundleName + "-ca"
	bundle := string(ca.BundlePEM())
	k.must(http.MethodPost, "/apis/trstctl.com/v1alpha1/trustbundles", "", map[string]any{
		"apiVersion": "trstctl.com/v1alpha1", "kind": "TrustBundle", "metadata": map[string]any{"name": bundleName},
		"spec": map[string]any{"caBundlePEM": bundle, "target": map[string]any{"configMapName": bundleName + "-ca", "namespaces": []any{ns}}},
	})
	t.Cleanup(func() {
		k.do(http.MethodDelete, "/apis/trstctl.com/v1alpha1/trustbundles/"+bundleName, "", nil)
		k.do(http.MethodDelete, configMapPath, "", nil)
	})
	distributed := func() bool {
		st, obj := k.do(http.MethodGet, configMapPath, "", nil)
		return st == http.StatusOK && at(obj, "data", "ca-bundle.pem") == bundle
	}
	waitFor("the TrustBundle reached its namespace", 10*time.Second, distributed)
	waitFor("the TrustBundle was marked Ready", 10*time.Second, func() bool {
		conditions, _ := at(k.get("/apis/trstctl.com/v1alpha1/trustbundles/"+bundleName), "status", "conditions").([]any)
		return len(conditions) == 1 && at(conditions[0], "status") == "True"
	})
	k.must(http.MethodDelete, configMapPath, "", nil)
	waitFor("the deleted ConfigMap was restored", 10*time.Second, distributed)

	// Native CertificateSigningRequest, approved by the admin identity.
	key, err := mtls.GenerateAgentKey("watch-" + suffix + "." + ns + ".svc")
	if err != nil {
		t.Fatal(err)
	}
	der, err := key.CSR()
	if err != nil {
		t.Fatal(err)
	}
	csrName := "trstctl-watch-" + suffix
	csrPath := "/apis/certificates.k8s.io/v1/certificatesigningrequests/" + csrName
	k.must(http.MethodPost, "/apis/certificates.k8s.io/v1/certificatesigningrequests", "", map[string]any{
		"apiVersion": "certificates.k8s.io/v1", "kind": "CertificateSigningRequest", "metadata": map[string]any{"name": csrName},
		"spec": map[string]any{
			"request":    base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})),
			"signerName": "trstctl.com/trstctl", "usages": []any{"digital signature", "client auth"},
		},
	})
	t.Cleanup(func() { k.do(http.MethodDelete, csrPath, "", nil) })
	csr := k.get(csrPath)
	csr["status"] = map[string]any{"conditions": []any{map[string]any{
		"type": "Approved", "status": "True", "reason": "E2EApprove", "message": "approved by the e2e admin identity",
	}}}
	k.must(http.MethodPut, csrPath+"/approval", "", csr)
	waitFor("the approved CSR was signed", 10*time.Second, func() bool {
		return at(k.get(csrPath), "status", "certificate") != nil
	})

	// Native trstctl Certificate on an eight-second issuer: issued, then
	// renewed two thirds of the way through.
	certName := "trstctl-watch-" + suffix
	secretPath := "/api/v1/namespaces/" + ns + "/secrets/" + certName + "-tls"
	k.must(http.MethodPost, "/apis/trstctl.com/v1alpha1/namespaces/"+ns+"/certificates", "", map[string]any{
		"apiVersion": "trstctl.com/v1alpha1", "kind": "Certificate", "metadata": map[string]any{"name": certName},
		"spec": map[string]any{
			"secretName": certName + "-tls", "dnsNames": []any{certName + "." + ns + ".svc"},
			"issuerRef": map[string]any{"name": short, "kind": "ClusterIssuer", "group": "trstctl.com"},
		},
	})
	t.Cleanup(func() {
		k.do(http.MethodDelete, "/apis/trstctl.com/v1alpha1/namespaces/"+ns+"/certificates/"+certName, "", nil)
		k.do(http.MethodDelete, secretPath, "", nil)
	})
	issued := func() string {
		st, obj := k.do(http.MethodGet, secretPath, "", nil)
		if st != http.StatusOK {
			return ""
		}
		value, _ := at(obj, "data", "tls.crt").(string)
		return value
	}
	waitFor("the Certificate was issued into its Secret", 10*time.Second, func() bool { return issued() != "" })
	first := issued()
	certPath := "/apis/trstctl.com/v1alpha1/namespaces/" + ns + "/certificates/" + certName
	// The Secret is written before the status that records it; a status the
	// CRD schema pruned would never show these fields.
	waitFor("the issuance was recorded in status", 10*time.Second, func() bool {
		status := at(k.get(certPath), "status")
		return at(status, "renewalTime") != nil && at(status, "specHash") != nil && at(status, "notAfter") != nil
	})
	waitFor("the Certificate was renewed before it expired", 12*time.Second, func() bool {
		current := issued()
		return current != "" && current != first
	})

	// A138: a TrustBundle the control plane rolls out to this cluster is
	// created with the agent's own service account (rbac.yaml) and then
	// distributed by the running controller.
	rolledName := "trstctl-rollout-" + suffix
	rolledConfigMap := "/api/v1/namespaces/" + ns + "/configmaps/" + rolledName
	t.Cleanup(func() {
		k.do(http.MethodDelete, "/apis/trstctl.com/v1alpha1/trustbundles/"+rolledName, "", nil)
		k.do(http.MethodDelete, rolledConfigMap, "", nil)
	})
	normalized := strings.TrimSpace(bundle) + "\n"
	if n, err := controller.ApplyDesiredTrustBundles(context.Background(), []k8s.DesiredTrustBundle{{
		RolloutID: "33333333-3333-4333-8333-333333333333", Name: rolledName, CABundlePEM: normalized, BundleSHA256: crypto.SHA256Hex([]byte(normalized)),
		ConfigMapName: rolledName, Key: "ca-bundle.pem", Namespaces: []string{ns},
	}}); err != nil || n != 1 {
		t.Fatalf("apply the rolled-out TrustBundle as the agent: %d, %v", n, err)
	}
	waitFor("the rolled-out TrustBundle was distributed", 10*time.Second, func() bool {
		st, obj := k.do(http.MethodGet, rolledConfigMap, "", nil)
		return st == http.StatusOK && at(obj, "data", "ca-bundle.pem") == normalized
	})
}
