// SPDX-License-Identifier: BUSL-1.1

//go:build e2e

package kubernetes_e2e

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/agent/k8s"
	"trstctl.com/trstctl/internal/crypto/mtls"
)

// TestTrustBundleSecretAndClusterTrustBundleTargets runs the agent's
// controller with its own least-privilege service account against a real API
// server. A TrustBundle with a Secret target in another namespace reports, on
// its own status, the opt-in grant it needs; once deploy/kubernetes/
// rbac-trust-secrets.yaml is applied the Secret is written. Where the cluster
// serves ClusterTrustBundle the bundle is published as one, a pod reads it
// through a projected clusterTrustBundle volume, and a changed bundle reaches
// the running pod; where it does not, the status says how to enable the API.
func TestTrustBundleSecretAndClusterTrustBundleTargets(t *testing.T) {
	requireIndependentApprover(t)
	client, raw, _ := cluster(t)
	k := newKubeAPI(t)
	applyCRDFile(k, filepath.Join("..", "..", "..", "deploy", "kubernetes", "certmanager-issuer-crds.yaml"))
	grant := manifestDocuments(t, filepath.Join("..", "..", "..", "deploy", "kubernetes", "rbac-trust-secrets.yaml"))
	granted := func() bool {
		st, _ := k.do(http.MethodGet, "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings/trstctl-agent-trust-secrets", "", nil)
		return st == http.StatusOK
	}
	if granted() {
		t.Skip("rbac-trust-secrets.yaml is already applied to this cluster; the test proves the cluster without it first")
	}

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	namespace := "trust-targets-" + suffix
	k.must(http.MethodPost, "/api/v1/namespaces", "", map[string]any{"apiVersion": "v1", "kind": "Namespace", "metadata": map[string]any{"name": namespace}})
	t.Cleanup(func() { k.do(http.MethodDelete, "/api/v1/namespaces/"+namespace, "", nil) })

	controller, err := k8s.NewIssuerController(client, k8s.SignerFunc(func(context.Context, []byte, time.Duration) ([]byte, error) {
		return nil, errors.New("this test signs nothing")
	}), "trstctl.com", "https://trstctl.trstctl.svc/api/v1/ca/authorities/e2e/issue")
	if err != nil {
		t.Fatal(err)
	}
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

	first, err := mtls.NewCA("trust targets e2e first")
	if err != nil {
		t.Fatal(err)
	}
	normalized := func(ca *mtls.CA) string { return strings.TrimSpace(string(ca.BundlePEM())) + "\n" }
	bundleName := "trust-targets-" + suffix
	bundlePath := "/apis/trstctl.com/v1alpha1/trustbundles/" + bundleName
	secretPath := "/api/v1/namespaces/" + namespace + "/secrets/" + bundleName + "-ca"
	k.must(http.MethodPost, "/apis/trstctl.com/v1alpha1/trustbundles", "", map[string]any{
		"apiVersion": "trstctl.com/v1alpha1", "kind": "TrustBundle", "metadata": map[string]any{"name": bundleName},
		"spec": map[string]any{"caBundlePEM": string(first.BundlePEM()), "target": map[string]any{
			"namespaces": []any{namespace}, "secret": map[string]any{"name": bundleName + "-ca"},
		}},
	})
	t.Cleanup(func() { k.do(http.MethodDelete, bundlePath, "", nil) })
	ready := func() (string, string) {
		conditions, _ := at(k.get(bundlePath), "status", "conditions").([]any)
		for _, condition := range conditions {
			if at(condition, "type") == "Ready" {
				status, _ := at(condition, "status").(string)
				message, _ := at(condition, "message").(string)
				return status, message
			}
		}
		return "", ""
	}
	notReadyWith := func(want string) func() bool {
		return func() bool {
			status, message := ready()
			return status == "False" && strings.Contains(message, want)
		}
	}
	waitUntil(t, "the TrustBundle reports the grant its Secret target needs", time.Minute, notReadyWith("apply deploy/kubernetes/rbac-trust-secrets.yaml"))

	for _, doc := range grant {
		kind, _ := doc["kind"].(string)
		name, _ := at(doc, "metadata", "name").(string)
		collection := csiTrustCollection(kind, "")
		k.must(http.MethodPost, collection, "", doc)
		t.Cleanup(func() { k.do(http.MethodDelete, collection+"/"+name, "", nil) })
	}
	touch := func() {
		bundle := k.get(bundlePath)
		meta := bundle["metadata"].(map[string]any)
		annotations, _ := meta["annotations"].(map[string]any)
		if annotations == nil {
			annotations = map[string]any{}
		}
		annotations["e2e.trstctl.com/touched"] = time.Now().Format(time.RFC3339Nano)
		meta["annotations"] = annotations
		k.must(http.MethodPut, bundlePath, "", bundle)
	}
	touch()
	secretHolds := func(ca *mtls.CA) func() bool {
		return func() bool {
			st, obj := k.do(http.MethodGet, secretPath, "", nil)
			encoded, _ := at(obj, "data", "ca.crt").(string)
			decoded, _ := base64.StdEncoding.DecodeString(encoded)
			return st == http.StatusOK && at(obj, "type") == "Opaque" && string(decoded) == normalized(ca)
		}
	}
	waitUntil(t, "the granted Secret target holds the bundle", time.Minute, secretHolds(first))
	waitUntil(t, "the TrustBundle is Ready with its Secret target", time.Minute, func() bool {
		status, _ := ready()
		return status == "True" && at(k.get(bundlePath), "status", "secretTargets") == float64(1)
	})

	// ClusterTrustBundle target.
	_, discovery := k.do(http.MethodGet, "/apis/certificates.k8s.io/v1beta1", "", nil)
	resources, _ := discovery["resources"].([]any)
	served := slices.ContainsFunc(resources, func(r any) bool { return at(r, "name") == "clustertrustbundles" })
	bundle := k.get(bundlePath)
	bundle["spec"].(map[string]any)["target"].(map[string]any)["clusterTrustBundle"] = map[string]any{"name": bundleName}
	k.must(http.MethodPut, bundlePath, "", bundle)
	ctbPath := "/apis/certificates.k8s.io/v1beta1/clustertrustbundles/" + bundleName
	t.Cleanup(func() { k.do(http.MethodDelete, ctbPath, "", nil) })
	if !served {
		waitUntil(t, "the TrustBundle says how to enable ClusterTrustBundle", time.Minute, notReadyWith("does not serve the ClusterTrustBundle API"))
		t.Log("this cluster does not serve ClusterTrustBundle; the projected-volume half needs a cluster that does")
		return
	}
	ctbHolds := func(ca *mtls.CA) func() bool {
		return func() bool {
			st, obj := k.do(http.MethodGet, ctbPath, "", nil)
			return st == http.StatusOK && at(obj, "spec", "trustBundle") == normalized(ca) && at(obj, "metadata", "labels", "trstctl.com/trust-bundle") == bundleName
		}
	}
	waitUntil(t, "the ClusterTrustBundle holds the bundle", time.Minute, ctbHolds(first))
	waitUntil(t, "the TrustBundle is Ready with its ClusterTrustBundle", time.Minute, func() bool {
		status, _ := ready()
		return status == "True" && at(k.get(bundlePath), "status", "clusterTrustBundle") == bundleName
	})

	waitUntil(t, "the namespace has its default service account", time.Minute, func() bool {
		st, _ := k.do(http.MethodGet, "/api/v1/namespaces/"+namespace+"/serviceaccounts/default", "", nil)
		return st == http.StatusOK
	})
	podName := "ctb-reader"
	k.must(http.MethodPost, "/api/v1/namespaces/"+namespace+"/pods", "", map[string]any{
		"apiVersion": "v1", "kind": "Pod", "metadata": map[string]any{"name": podName},
		"spec": map[string]any{
			"restartPolicy":                "Never",
			"automountServiceAccountToken": false,
			"containers": []any{map[string]any{
				"name": "reader", "image": "registry.k8s.io/e2e-test-images/busybox:1.29-4",
				"command":      []any{"sh", "-c", "while true; do cat /trust/ca.crt; sleep 5; done"},
				"volumeMounts": []any{map[string]any{"name": "trust", "mountPath": "/trust", "readOnly": true}},
			}},
			"volumes": []any{map[string]any{"name": "trust", "projected": map[string]any{"sources": []any{
				map[string]any{"clusterTrustBundle": map[string]any{"name": bundleName, "path": "ca.crt"}},
			}}}},
		},
	})
	waitUntil(t, "the pod reads the ClusterTrustBundle from its projected volume", 3*time.Minute, func() bool {
		return strings.Contains(podLog(raw, namespace, podName), pemMarker(first.BundlePEM()))
	})

	second, err := mtls.NewCA("trust targets e2e second")
	if err != nil {
		t.Fatal(err)
	}
	bundle = k.get(bundlePath)
	bundle["spec"].(map[string]any)["caBundlePEM"] = string(second.BundlePEM())
	k.must(http.MethodPut, bundlePath, "", bundle)
	waitUntil(t, "the Secret and ClusterTrustBundle hold the changed bundle", time.Minute, func() bool {
		return secretHolds(second)() && ctbHolds(second)()
	})
	waitUntil(t, "the running pod reads the changed bundle", 4*time.Minute, func() bool {
		return strings.Contains(podLog(raw, namespace, podName), pemMarker(second.BundlePEM()))
	})
}
