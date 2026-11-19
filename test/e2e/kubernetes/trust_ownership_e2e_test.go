// SPDX-License-Identifier: BUSL-1.1

//go:build e2e

package kubernetes_e2e

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/container-storage-interface/spec/lib/go/csi"

	"trstctl.com/trstctl/internal/agent/csitrust"
	"trstctl.com/trstctl/internal/agent/k8s"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/mtls"
)

// CR-431 and CR-759. Exercise the real Kubernetes CRD and the driver's publish
// entry point with a disposable public certificate and an empty volume path.
func TestTrustCSIRefusesStoredRolloutsWithoutConsent(t *testing.T) {
	requireIndependentApprover(t)
	client, _, ns := cluster(t)
	k := newKubeAPI(t)
	applyCRDFile(k, filepath.Join("..", "..", "..", "deploy", "kubernetes", "certmanager-issuer-crds.yaml"))
	ca, err := mtls.NewCA("Kubernetes trust ownership e2e root")
	if err != nil {
		t.Fatal(err)
	}
	bundle := ca.BundlePEM()
	policy, err := k8s.ParseTrustDistributionPolicy(false, ns)
	if err != nil {
		t.Fatal(err)
	}
	controller, err := k8s.NewIssuerController(client, k8s.SignerFunc(func(context.Context, []byte, time.Duration) ([]byte, error) {
		return nil, errors.New("this trust fixture signs no requests")
	}), k8s.DefaultIssuerGroup, "https://trstctl.trstctl.svc/api/v1/ca/authorities/e2e/issue", policy)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		done <- controller.Run(ctx, k8s.RunOptions{ClusterID: client.ClusterID(), ReportEvery: 10 * time.Minute, Resync: 10 * time.Minute})
	}()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("run trust watcher: %v", err)
		}
	})
	for _, tc := range []struct {
		name   string
		remote bool
		null   bool
	}{
		{name: "local-defaults"},
		{name: "stored-rollout", remote: true},
		{name: "null-target", null: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			name := fmt.Sprintf("%s-%d", tc.name, time.Now().UnixNano())
			meta := map[string]any{"name": name}
			if tc.remote {
				meta["labels"] = map[string]string{"app.kubernetes.io/managed-by": "trstctl-agent"}
				meta["annotations"] = map[string]string{
					"trstctl.com/rollout-id": "11111111-1111-4111-8111-111111111111", "trstctl.com/rollout-sha256": crypto.SHA256Hex(bundle),
				}
			}
			target := map[string]any{"namespaces": []string{ns}}
			if tc.null {
				target["secret"] = nil
			}
			const collection = "/apis/trstctl.com/v1alpha1/trustbundles"
			path := collection + "/" + name
			k.must(http.MethodPost, collection, "", map[string]any{
				"apiVersion": "trstctl.com/v1alpha1", "kind": "TrustBundle", "metadata": meta,
				"spec": map[string]any{"caBundlePEM": string(bundle), "target": target},
			})
			configMap := "/api/v1/namespaces/" + ns + "/configmaps/" + name
			t.Cleanup(func() {
				k.do(http.MethodDelete, path, "", nil)
				k.do(http.MethodDelete, configMap, "", nil)
			})
			wantStatus := "True"
			if tc.remote || tc.null {
				wantStatus = "False"
			}
			waitUntil(t, "the watch reconciles this TrustBundle", 20*time.Second, func() bool {
				conditions, _ := at(k.get(path), "status", "conditions").([]any)
				for _, condition := range conditions {
					if at(condition, "type") == "Ready" && at(condition, "status") == wantStatus {
						return wantStatus == "True" || at(condition, "reason") == "DistributionFailed"
					}
				}
				return false
			})
			status, installed := k.do(http.MethodGet, configMap, "", nil)
			if wantStatus == "False" && status != http.StatusNotFound {
				t.Fatalf("refused watch reconciliation left a target, status=%d", status)
			}
			if wantStatus == "True" && (status != http.StatusOK || at(installed, "data", "ca-bundle.pem") != string(bundle)) {
				t.Fatalf("omitted defaults did not install the exact public bundle, status=%d", status)
			}
			live := at(k.get(path), "spec", "target").(map[string]any)
			if value, present := live["secret"]; present != tc.null || value != nil {
				t.Errorf("Kubernetes lost explicit optional target presence: present=%v, want %v", present, tc.null)
			}
			if live["key"] != "ca-bundle.pem" {
				t.Errorf("Kubernetes failed to default omitted ConfigMap data key: %v", live["key"])
			}
			volume := t.TempDir()
			driver := csitrust.NewDriver(client, "test-node", "test")
			_, err := driver.NodePublishVolume(t.Context(), &csi.NodePublishVolumeRequest{
				TargetPath: volume,
				VolumeContext: map[string]string{
					"csi.storage.k8s.io/ephemeral": "true", csitrust.AttributeTrustBundle: name,
				},
			})
			got, statErr := os.ReadFile(filepath.Join(volume, "ca.crt"))
			if tc.remote || tc.null {
				if err == nil || !errors.Is(statErr, os.ErrNotExist) {
					t.Fatalf("ineligible bundle was published, CSI error=%v, file error=%v", err, statErr)
				}
				return
			}
			if err != nil || statErr != nil || string(got) != string(bundle) {
				t.Fatalf("local bundle did not publish exact bytes, CSI error=%v, file error=%v", err, statErr)
			}
		})
	}
}
