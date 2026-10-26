// SPDX-License-Identifier: BUSL-1.1

package k8s

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
)

// DesiredTrustBundle is one TrustBundle the control plane is rolling out to
// this cluster (A138): public CA certificates only, and where to put them.
type DesiredTrustBundle struct {
	RolloutID     string
	Name          string
	CABundlePEM   string
	BundleSHA256  string
	ConfigMapName string
	Key           string
	Namespaces    []string
}

const trustRolloutAnnotation = "trstctl.com/rollout-id"

// ApplyDesiredTrustBundles makes each desired TrustBundle exist as a
// cluster-scoped object the agent owns. The watch-driven controller then
// distributes it, and the next posture report is what verifies the rollout
// here. A TrustBundle of the same name that someone else created is left alone
// (the rollout waits on this cluster), and a bundle that is not public
// certificates or does not match its hash is refused. It returns how many
// objects it wrote.
func (c *IssuerController) ApplyDesiredTrustBundles(ctx context.Context, desired []DesiredTrustBundle) (int, error) {
	written := 0
	var errs []error
	for _, bundle := range desired {
		wrote, err := c.applyDesiredTrustBundle(ctx, bundle)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if wrote {
			written++
		}
	}
	return written, errors.Join(errs...)
}

func (c *IssuerController) applyDesiredTrustBundle(ctx context.Context, bundle DesiredTrustBundle) (bool, error) {
	spec := map[string]any{
		"caBundlePEM": bundle.CABundlePEM,
		"target": map[string]any{
			"configMapName": bundle.ConfigMapName, "key": bundle.Key, "namespaces": stringsToAny(bundle.Namespaces),
		},
	}
	if _, hash, err := trustBundlePEM(spec); err != nil || hash != bundle.BundleSHA256 {
		return false, fmt.Errorf("k8s: rollout %s TrustBundle %s is not the public bundle it names: %v", bundle.RolloutID, bundle.Name, err)
	}
	path := trustBundleCollectionPath() + "/" + bundle.Name
	st, body, err := c.client.request(ctx, http.MethodGet, path, nil)
	if err != nil {
		return false, err
	}
	if st == http.StatusNotFound {
		obj := map[string]any{
			"apiVersion": trstctlAPIVersion, "kind": "TrustBundle",
			"metadata": map[string]any{
				"name":        bundle.Name,
				"labels":      map[string]any{"app.kubernetes.io/managed-by": "trstctl-agent"},
				"annotations": map[string]any{trustRolloutAnnotation: bundle.RolloutID},
			},
			"spec": spec,
		}
		st, body, err = c.client.request(ctx, http.MethodPost, trustBundleCollectionPath(), obj)
		if err != nil {
			return false, err
		}
		if st/100 != 2 {
			return false, fmt.Errorf("k8s: create TrustBundle %s for rollout %s: status %d: %s", bundle.Name, bundle.RolloutID, st, string(body))
		}
		return true, nil
	}
	if st/100 != 2 {
		return false, fmt.Errorf("k8s: read TrustBundle %s: status %d: %s", bundle.Name, st, string(body))
	}
	var live map[string]any
	if err := json.Unmarshal(body, &live); err != nil {
		return false, fmt.Errorf("k8s: decode TrustBundle %s: %w", bundle.Name, err)
	}
	meta, _ := live["metadata"].(map[string]any)
	labels, _ := meta["labels"].(map[string]any)
	if labels["app.kubernetes.io/managed-by"] != "trstctl-agent" {
		return false, fmt.Errorf("k8s: TrustBundle %s exists and was not created by the agent; rollout %s leaves it alone", bundle.Name, bundle.RolloutID)
	}
	annotations, _ := meta["annotations"].(map[string]any)
	if annotations == nil {
		annotations = map[string]any{}
	}
	if annotations[trustRolloutAnnotation] == bundle.RolloutID && trustBundleSpecEqual(live["spec"], spec) {
		return false, nil
	}
	annotations[trustRolloutAnnotation] = bundle.RolloutID
	meta["annotations"] = annotations
	live["spec"] = spec
	st, body, err = c.client.request(ctx, http.MethodPut, path, live)
	if err != nil {
		return false, err
	}
	if st/100 != 2 {
		return false, fmt.Errorf("k8s: update TrustBundle %s for rollout %s: status %d: %s", bundle.Name, bundle.RolloutID, st, string(body))
	}
	return true, nil
}

func trustBundleSpecEqual(live any, want map[string]any) bool {
	spec, _ := live.(map[string]any)
	target, _ := spec["target"].(map[string]any)
	wantTarget, _ := want["target"].(map[string]any)
	return spec["caBundlePEM"] == want["caBundlePEM"] &&
		nativeString(target, "configMapName") == wantTarget["configMapName"] &&
		nativeString(target, "key") == wantTarget["key"] &&
		slices.Equal(nativeStringList(target["namespaces"]), nativeStringList(wantTarget["namespaces"]))
}

func stringsToAny(values []string) []any {
	out := make([]any, 0, len(values))
	for _, value := range values {
		out = append(out, value)
	}
	return out
}
