// SPDX-License-Identifier: BUSL-1.1

//go:build e2e

package kubernetes_e2e

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto/mtls"
)

// csiTrustCollection maps the kinds csi-trust.yaml ships to their API
// collections.
func csiTrustCollection(kind, namespace string) string {
	switch kind {
	case "CSIDriver":
		return "/apis/storage.k8s.io/v1/csidrivers"
	case "ServiceAccount":
		return "/api/v1/namespaces/" + namespace + "/serviceaccounts"
	case "ClusterRole":
		return "/apis/rbac.authorization.k8s.io/v1/clusterroles"
	case "ClusterRoleBinding":
		return "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings"
	case "DaemonSet":
		return "/apis/apps/v1/namespaces/" + namespace + "/daemonsets"
	}
	return ""
}

// TestCSITrustDriverDeliversTrustBundlesToPods deploys the opt-in CSI trust
// driver (deploy/kubernetes/csi-trust.yaml) with the image in
// K8S_TRUST_CSI_IMAGE, mounts a TrustBundle into a pod through an inline CSI
// volume, and reads the bundle from inside the pod; after the TrustBundle
// changes, the kubelet's republish delivers the new bundle to the running pod.
func TestCSITrustDriverDeliversTrustBundlesToPods(t *testing.T) {
	image := os.Getenv("K8S_TRUST_CSI_IMAGE")
	if image == "" {
		t.Skip("K8S_TRUST_CSI_IMAGE not set; the CSI trust driver e2e needs an agent image loaded into the cluster")
	}
	_, raw, ns := cluster(t)
	k := newKubeAPI(t)
	applyCRDFile(k, filepath.Join("..", "..", "..", "deploy", "kubernetes", "certmanager-issuer-crds.yaml"))

	for _, doc := range manifestDocuments(t, filepath.Join("..", "..", "..", "deploy", "kubernetes", "csi-trust.yaml")) {
		kind, _ := doc["kind"].(string)
		name, _ := at(doc, "metadata", "name").(string)
		namespace, _ := at(doc, "metadata", "namespace").(string)
		if kind == "DaemonSet" {
			containers, _ := at(doc, "spec", "template", "spec", "containers").([]any)
			driver, _ := containers[0].(map[string]any)
			driver["image"] = image
			driver["imagePullPolicy"] = "IfNotPresent"
		}
		collection := csiTrustCollection(kind, namespace)
		if collection == "" {
			t.Fatalf("csi-trust.yaml ships a %s this test does not know how to apply", kind)
		}
		if st, _ := k.do(http.MethodGet, collection+"/"+name, "", nil); st == http.StatusOK {
			k.must(http.MethodDelete, collection+"/"+name, "", nil)
			k.waitGone(collection + "/" + name)
		}
		k.must(http.MethodPost, collection, "", doc)
		t.Cleanup(func() { k.do(http.MethodDelete, collection+"/"+name, "", nil) })
	}
	waitUntil(t, "the CSI trust driver is running on a node", 3*time.Minute, func() bool {
		status := at(k.get("/apis/apps/v1/namespaces/trstctl/daemonsets/trstctl-trust-csi"), "status")
		ready, _ := at(status, "numberReady").(float64)
		return ready >= 1
	})

	first, err := mtls.NewCA("csi trust e2e first")
	if err != nil {
		t.Fatal(err)
	}
	second, err := mtls.NewCA("csi trust e2e second")
	if err != nil {
		t.Fatal(err)
	}
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	bundleName := "csi-roots-" + suffix
	bundlePath := "/apis/trstctl.com/v1alpha1/trustbundles/" + bundleName
	k.must(http.MethodPost, "/apis/trstctl.com/v1alpha1/trustbundles", "", map[string]any{
		"apiVersion": "trstctl.com/v1alpha1", "kind": "TrustBundle", "metadata": map[string]any{"name": bundleName},
		"spec": map[string]any{"caBundlePEM": string(first.BundlePEM()), "target": map[string]any{"namespaces": []any{ns}}},
	})
	t.Cleanup(func() { k.do(http.MethodDelete, bundlePath, "", nil) })

	podName := "csi-trust-reader-" + suffix
	podPath := "/api/v1/namespaces/" + ns + "/pods/" + podName
	k.must(http.MethodPost, "/api/v1/namespaces/"+ns+"/pods", "", map[string]any{
		"apiVersion": "v1", "kind": "Pod", "metadata": map[string]any{"name": podName},
		"spec": map[string]any{
			"restartPolicy": "Never",
			"containers": []any{map[string]any{
				"name": "reader", "image": "registry.k8s.io/e2e-test-images/busybox:1.29-4",
				"command":      []any{"sh", "-c", "while true; do cat /trust/ca.crt; sleep 5; done"},
				"volumeMounts": []any{map[string]any{"name": "trust", "mountPath": "/trust", "readOnly": true}},
			}},
			"volumes": []any{map[string]any{"name": "trust", "csi": map[string]any{
				"driver": "trust.csi.trstctl.com", "readOnly": true,
				"volumeAttributes": map[string]any{"trustBundle": bundleName},
			}}},
		},
	})
	t.Cleanup(func() { k.do(http.MethodDelete, podPath, "", nil) })
	waitUntil(t, "the pod reads the TrustBundle from its CSI volume", 3*time.Minute, func() bool {
		return strings.Contains(podLog(raw, ns, podName), pemMarker(first.BundlePEM()))
	})
	bundle := k.get(bundlePath)
	bundle["spec"].(map[string]any)["caBundlePEM"] = string(second.BundlePEM())
	k.must(http.MethodPut, bundlePath, "", bundle)
	waitUntil(t, "the republished volume carries the changed TrustBundle", 4*time.Minute, func() bool {
		return strings.Contains(podLog(raw, ns, podName), pemMarker(second.BundlePEM()))
	})
}

// podLog returns the tail of a pod's log, or "" until it has one.
func podLog(raw func(string, string, any) (int, []byte), namespace, pod string) string {
	st, body := raw(http.MethodGet, "/api/v1/namespaces/"+namespace+"/pods/"+pod+"/log?"+url.Values{"tailLines": {"60"}}.Encode(), nil)
	if st != http.StatusOK {
		return ""
	}
	return string(body)
}

// pemMarker is a PEM certificate's last base64 line, unique to that
// certificate, to find it in a pod's log.
func pemMarker(pem []byte) string {
	lines := strings.Split(strings.TrimSpace(string(pem)), "\n")
	return lines[len(lines)-2]
}

func waitUntil(t *testing.T, what string, within time.Duration, cond func() bool) {
	t.Helper()
	start := time.Now()
	for !cond() {
		if time.Since(start) > within {
			t.Fatalf("not within %s: %s", within, what)
		}
		time.Sleep(2 * time.Second)
	}
	t.Logf("%s after %s", what, time.Since(start).Round(time.Second))
}
