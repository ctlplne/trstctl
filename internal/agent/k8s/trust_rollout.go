// SPDX-License-Identifier: BUSL-1.1

package k8s

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"reflect"

	"trstctl.com/trstctl/internal/kubetrust"
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
	if !c.trustPolicy.allowRemote {
		return false, permanent(errors.New("k8s: remote TrustBundle requires local --k8s-trust-rollouts opt-in"))
	}
	if !kubetrust.ValidRolloutID(bundle.RolloutID) {
		return false, permanent(errors.New("k8s: TrustBundle rollout ID must be a canonical nonzero UUID"))
	}
	if err := kubetrust.ValidateTargets(bundle.Name, bundle.ConfigMapName, bundle.Key, bundle.Namespaces); err != nil {
		return false, permanent(fmt.Errorf("k8s: TrustBundle rollout targets: %w", err))
	}
	if err := c.trustPolicy.admitNamespaces(bundle.Namespaces); err != nil {
		return false, permanent(err)
	}
	pem, hash, err := kubetrust.NormalizeBundle(bundle.CABundlePEM)
	if err != nil {
		return false, permanent(fmt.Errorf("k8s: rollout %s TrustBundle %s: %w", bundle.RolloutID, bundle.Name, err))
	}
	if hash != bundle.BundleSHA256 {
		return false, permanent(fmt.Errorf("k8s: rollout %s TrustBundle %s does not match its canonical bundle hash", bundle.RolloutID, bundle.Name))
	}
	spec := map[string]any{
		"caBundlePEM": pem,
		"target": map[string]any{
			"configMapName": bundle.ConfigMapName, "key": bundle.Key, "namespaces": stringsToAny(bundle.Namespaces),
		},
	}
	// The running controller writes the same object's status, so an update can
	// lose the optimistic-concurrency race (409 Conflict). Read it again and
	// reapply: a conflict says only that the object moved, not that this
	// rollout is wrong.
	for attempt := 1; ; attempt++ {
		wrote, conflict, err := c.applyDesiredTrustBundleOnce(ctx, bundle, spec)
		if !conflict || attempt == trustBundleUpdateAttempts {
			return wrote, err
		}
	}
}

// trustBundleUpdateAttempts bounds the read-modify-write retries one apply
// makes after update conflicts.
const trustBundleUpdateAttempts = 3

func (c *IssuerController) applyDesiredTrustBundleOnce(ctx context.Context, bundle DesiredTrustBundle, spec map[string]any) (bool, bool, error) {
	path := trustBundleCollectionPath() + "/" + url.PathEscape(bundle.Name)
	st, body, err := c.client.request(ctx, http.MethodGet, path, nil)
	if err != nil {
		return false, false, err
	}
	if st == http.StatusNotFound {
		obj := map[string]any{
			"apiVersion": trstctlAPIVersion, "kind": "TrustBundle",
			"metadata": map[string]any{
				"name":        bundle.Name,
				"labels":      map[string]any{"app.kubernetes.io/managed-by": "trstctl-agent"},
				"annotations": map[string]any{trustRolloutAnnotation: bundle.RolloutID, trustRolloutHashAnnotation: bundle.BundleSHA256},
			},
			"spec": spec,
		}
		st, body, err = c.client.request(ctx, http.MethodPost, trustBundleCollectionPath(), obj)
		if err != nil {
			return false, false, err
		}
		if st/100 != 2 {
			return false, st == http.StatusConflict, fmt.Errorf("k8s: create TrustBundle %s for rollout %s: status %d: %s", bundle.Name, bundle.RolloutID, st, string(body))
		}
		return true, false, nil
	}
	if st/100 != 2 {
		return false, false, fmt.Errorf("k8s: read TrustBundle %s: status %d: %s", bundle.Name, st, string(body))
	}
	var live map[string]any
	if err := json.Unmarshal(body, &live); err != nil {
		return false, false, fmt.Errorf("k8s: decode TrustBundle %s: %w", bundle.Name, err)
	}
	meta, _ := live["metadata"].(map[string]any)
	origin, originErr := trustBundleOrigin(meta)
	if originErr != nil || origin.rolloutID == "" || origin.hashPresent && !kubetrust.ValidBundleHash(origin.hash) {
		return false, false, permanent(fmt.Errorf("k8s: TrustBundle %s was not created by the agent with a valid rollout identity; rollout %s leaves it alone", bundle.Name, bundle.RolloutID))
	}
	if origin.rolloutID == bundle.RolloutID && origin.hash == bundle.BundleSHA256 && reflect.DeepEqual(live["spec"], spec) {
		return false, false, nil
	}
	annotations := meta["annotations"].(map[string]any)
	annotations[trustRolloutAnnotation] = bundle.RolloutID
	annotations[trustRolloutHashAnnotation] = bundle.BundleSHA256
	live["spec"] = spec
	st, body, err = c.client.request(ctx, http.MethodPut, path, live)
	if err != nil {
		return false, false, err
	}
	if st == http.StatusConflict {
		return false, true, fmt.Errorf("k8s: update TrustBundle %s for rollout %s: status %d: %s", bundle.Name, bundle.RolloutID, st, string(body))
	}
	if st/100 != 2 {
		return false, false, fmt.Errorf("k8s: update TrustBundle %s for rollout %s: status %d: %s", bundle.Name, bundle.RolloutID, st, string(body))
	}
	return true, false, nil
}

func stringsToAny(values []string) []any {
	out := make([]any, 0, len(values))
	for _, value := range values {
		out = append(out, value)
	}
	return out
}
