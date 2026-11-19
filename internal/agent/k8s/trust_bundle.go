// SPDX-License-Identifier: BUSL-1.1

package k8s

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"trstctl.com/trstctl/internal/kubetrust"
)

func configMapCollectionPath(namespace string) string {
	return fmt.Sprintf("/api/v1/namespaces/%s/configmaps", url.PathEscape(namespace))
}

func configMapItemPath(namespace, name string) string {
	return configMapCollectionPath(namespace) + "/" + url.PathEscape(name)
}

func (c *IssuerController) reconcileTrustBundles(ctx context.Context) (int, []PostureResource, error) {
	st, body, err := c.client.request(ctx, http.MethodGet, trustBundleCollectionPath(), nil)
	if err != nil {
		return 0, nil, err
	}
	if st == http.StatusNotFound {
		return 0, nil, fmt.Errorf("k8s: TrustBundle CRD is not installed")
	}
	if st/100 != 2 {
		return 0, nil, fmt.Errorf("k8s: list trstctl TrustBundle resources: status %d: %s", st, string(body))
	}
	var list struct {
		Items []map[string]any `json:"items"`
	}
	if err := json.Unmarshal(body, &list); err != nil {
		return 0, nil, fmt.Errorf("k8s: decode trstctl TrustBundle list: %w", err)
	}

	writes := 0
	var refusal error
	posture := make([]PostureResource, 0, len(list.Items))
	for _, bundle := range list.Items {
		n, current, err := c.syncTrustBundle(ctx, bundle)
		writes += n
		posture = append(posture, current)
		if err == nil {
			continue
		}
		var invalid permanentError
		if !errors.As(err, &invalid) {
			return writes, posture, err
		}
		if refusal == nil {
			refusal = err
		}
	}
	return writes, posture, refusal
}

// syncTrustBundle converges one bundle: every target ConfigMap holds it and
// its status reports it. Nothing is written when both already agree, so a
// watch on these objects does not wake the controller with its own writes. It
// returns how many ConfigMaps it wrote and the bundle's posture.
func (c *IssuerController) syncTrustBundle(ctx context.Context, bundle map[string]any) (int, PostureResource, error) {
	current := trustBundlePosture(bundle)
	n, targets, hash, err := c.distributeTrustBundle(ctx, bundle)
	if err != nil {
		if markErr := c.markTrustBundleNotReady(ctx, bundle, err); markErr != nil {
			err = fmt.Errorf("%w (recording it on the TrustBundle also failed: %v)", err, markErr)
		}
		return n, failedPosture(current), err
	}
	if trustBundleStatusCurrent(bundle, targets, hash) {
		if n == 0 {
			return 0, current, nil
		}
		current.State, current.Reason, current.PublicHash = "ready", "distributed", hash
		return n, current, nil
	}
	current.PublicHash = hash
	updated, err := c.markTrustBundleReady(ctx, bundle, targets, hash)
	if err != nil {
		return n, failedPosture(current), err
	}
	// Bind posture to the API server's post-status-update object so the
	// reported resourceVersion is the one independently readable from the
	// cluster after reconciliation.
	current = trustBundlePosture(updated)
	current.State, current.Reason, current.PublicHash = "ready", "distributed", hash
	return n, current, nil
}

// distributeTrustBundle writes the bundle to every target that does not
// already hold it — the ConfigMap in each target namespace and, when named, a
// Secret in each and a ClusterTrustBundle — returning how many objects it
// wrote, where the bundle is distributed, and its hash.
func (c *IssuerController) distributeTrustBundle(ctx context.Context, obj map[string]any) (int, trustBundleTargets, string, error) {
	bundle, err := parseStoredTrustBundle(obj, c.trustPolicy.allowRemote, true)
	if err == nil {
		err = c.trustPolicy.admitNamespaces(bundle.namespaces)
	}
	if err != nil {
		return 0, trustBundleTargets{}, "", permanent(fmt.Errorf("k8s: TrustBundle %q: %w", objectName(obj), err))
	}
	targets := trustBundleTargets{Namespaces: len(bundle.namespaces), ClusterTrustBundle: bundle.clusterTrustBundle}
	written := 0
	count := func(wrote bool) {
		if wrote {
			written++
		}
	}
	for _, namespace := range bundle.namespaces {
		dest := configMapDestination{client: c.client, namespace: namespace, name: bundle.configMap, bundleName: bundle.name}
		wrote, err := dest.Install(ctx, bundle.key, bundle.pem, bundle.hash)
		if err != nil {
			return written, targets, "", err
		}
		count(wrote)
		if bundle.secret != nil {
			wrote, err := c.installTrustSecret(ctx, namespace, bundle.name, *bundle.secret, bundle.pem, bundle.hash)
			if err != nil {
				return written, targets, "", err
			}
			count(wrote)
			targets.Secrets++
		}
	}
	if bundle.clusterTrustBundle != "" {
		wrote, err := c.installClusterTrustBundle(ctx, bundle.clusterTrustBundle, bundle.name, bundle.pem, bundle.hash)
		if err != nil {
			return written, targets, "", err
		}
		count(wrote)
	}
	return written, targets, bundle.hash, nil
}

// trustBundleStatusCurrent reports whether the status already records this
// distribution, so it need not be written again.
func trustBundleStatusCurrent(obj map[string]any, targets trustBundleTargets, hash string) bool {
	status, _ := obj["status"].(map[string]any)
	if stringField(status, "bundleSHA256") != hash || stringField(status, "clusterTrustBundle") != targets.ClusterTrustBundle {
		return false
	}
	if statusCount(status, "targets") != targets.Namespaces || statusCount(status, "secretTargets") != targets.Secrets {
		return false
	}
	conds, _ := status["conditions"].([]any)
	want := trustBundleReadyCondition(targets)
	for _, raw := range conds {
		cond, _ := raw.(map[string]any)
		if cond["type"] == "Ready" {
			return cond["status"] == want["status"] && cond["reason"] == want["reason"] && cond["message"] == want["message"]
		}
	}
	return false
}

// statusCount reads an integer status field as decoded JSON or as written.
func statusCount(status map[string]any, key string) int {
	switch value := status[key].(type) {
	case float64:
		return int(value)
	case int:
		return value
	default:
		return 0
	}
}

func trustBundlePEM(spec map[string]any) (string, string, error) {
	bundle, ok := spec["caBundlePEM"].(string)
	if !ok || bundle == "" {
		return "", "", fmt.Errorf("spec.caBundlePEM must be a nonempty public PEM string")
	}
	return kubetrust.NormalizeBundle(bundle)
}

type configMapDestination struct {
	client     *Client
	namespace  string
	name       string
	bundleName string
}

// Install makes the ConfigMap hold the bundle under key, reporting whether it
// wrote. An existing ConfigMap keeps its other keys, labels and annotations; it
// is not rewritten when it already holds this bundle.
func (d configMapDestination) Install(ctx context.Context, key, bundlePEM, hash string) (bool, error) {
	if !kubetrust.ValidBundleName(d.bundleName) || !kubetrust.ValidTargetName(d.name) || !kubetrust.ValidTrustNamespace(d.namespace) || !kubetrust.ValidDataKey(key) {
		return false, permanent(fmt.Errorf("k8s: invalid TrustBundle ConfigMap target %q/%q", d.namespace, d.name))
	}
	for attempt := 1; ; attempt++ {
		wrote, conflict, err := d.installOnce(ctx, key, bundlePEM, hash)
		if !conflict || attempt == trustBundleUpdateAttempts {
			return wrote, err
		}
	}
}

func (d configMapDestination) installOnce(ctx context.Context, key, bundlePEM, hash string) (bool, bool, error) {
	path := configMapItemPath(d.namespace, d.name)
	status, body, err := d.client.request(ctx, http.MethodGet, path, nil)
	if err != nil {
		return false, false, err
	}
	method, action := http.MethodPut, "update"
	var live map[string]any
	switch status {
	case http.StatusOK:
		if err := json.Unmarshal(body, &live); err != nil {
			return false, false, fmt.Errorf("k8s: decode ConfigMap %s/%s: %w", d.namespace, d.name, err)
		}
		meta, _ := live["metadata"].(map[string]any)
		if !trustObjectOwned(meta, d.bundleName) {
			return false, false, permanent(fmt.Errorf("k8s: ConfigMap %s/%s exists and was not created for TrustBundle %s; rename the target or remove it", d.namespace, d.name, d.bundleName))
		}
		annotations, _ := meta["annotations"].(map[string]any)
		data, _ := live["data"].(map[string]any)
		if data[key] == bundlePEM && annotations["trstctl.com/bundle-sha256"] == hash {
			return false, false, nil
		}
		if annotations == nil {
			annotations = map[string]any{}
		}
		if data == nil {
			data = map[string]any{}
		}
		annotations["trstctl.com/bundle-sha256"] = hash
		data[key] = bundlePEM
		meta["annotations"], live["data"] = annotations, data
	case http.StatusNotFound:
		method, action, path = http.MethodPost, "create", configMapCollectionPath(d.namespace)
		meta := map[string]any{
			"name": d.name, "namespace": d.namespace, "labels": trustObjectLabels(d.bundleName),
			"annotations": map[string]any{"trstctl.com/bundle-sha256": hash},
		}
		live = configMapObject(meta, map[string]string{key: bundlePEM})
	default:
		return false, false, fmt.Errorf("k8s: read ConfigMap %s/%s: status %d: %s", d.namespace, d.name, status, string(body))
	}
	status, body, err = d.client.request(ctx, method, path, live)
	if err != nil {
		return false, false, err
	}
	if status/100 != 2 {
		return false, status == http.StatusConflict, fmt.Errorf("k8s: %s ConfigMap %s/%s: status %d: %s", action, d.namespace, d.name, status, string(body))
	}
	return true, false, nil
}

func configMapObject(meta map[string]any, data map[string]string) map[string]any {
	return map[string]any{
		"apiVersion": "v1",
		"kind":       "ConfigMap",
		"metadata":   meta,
		"data":       data,
	}
}

func (c *IssuerController) markTrustBundleReady(ctx context.Context, obj map[string]any, targets trustBundleTargets, hash string) (map[string]any, error) {
	name, _, err := trustBundleIdentity(obj)
	if err != nil {
		return nil, permanent(err)
	}
	status, _ := obj["status"].(map[string]any)
	if status == nil {
		status = map[string]any{}
	}
	status["targets"] = targets.Namespaces
	status["bundleSHA256"] = hash
	delete(status, "secretTargets")
	if targets.Secrets > 0 {
		status["secretTargets"] = targets.Secrets
	}
	delete(status, "clusterTrustBundle")
	if targets.ClusterTrustBundle != "" {
		status["clusterTrustBundle"] = targets.ClusterTrustBundle
	}
	status["conditions"] = upsertTrustBundleReady(status["conditions"], targets)
	obj["status"] = status

	st, body, err := c.client.request(ctx, http.MethodPut, trustBundleCollectionPath()+"/"+url.PathEscape(name)+"/status", obj)
	if err != nil {
		return nil, err
	}
	if st/100 != 2 {
		return nil, fmt.Errorf("k8s: update trstctl TrustBundle %s status: %d: %s", name, st, string(body))
	}
	var updated map[string]any
	if err := json.Unmarshal(body, &updated); err != nil {
		return nil, fmt.Errorf("k8s: decode updated trstctl TrustBundle %s: %w", name, err)
	}
	return updated, nil
}

// markTrustBundleNotReady records on the TrustBundle why it could not be
// distributed, so its status never keeps claiming an earlier distribution while
// a target it now names is missing. It writes only when the reason changed.
func (c *IssuerController) markTrustBundleNotReady(ctx context.Context, obj map[string]any, cause error) error {
	name, _, err := trustBundleIdentity(obj)
	if err != nil {
		return nil
	}
	notReady := map[string]any{
		"type":    "Ready",
		"status":  "False",
		"reason":  "DistributionFailed",
		"message": "trstctl TrustBundle not distributed: " + cause.Error(),
	}
	status, _ := obj["status"].(map[string]any)
	if status == nil {
		status = map[string]any{}
	}
	conds, _ := status["conditions"].([]any)
	replaced := false
	for i, condition := range conds {
		item, ok := condition.(map[string]any)
		if !ok || item["type"] != "Ready" {
			continue
		}
		if item["status"] == notReady["status"] && item["reason"] == notReady["reason"] && item["message"] == notReady["message"] {
			return nil
		}
		conds[i], replaced = notReady, true
	}
	if !replaced {
		conds = append(conds, notReady)
	}
	status["conditions"] = conds
	obj["status"] = status
	st, body, err := c.client.request(ctx, http.MethodPut, trustBundleCollectionPath()+"/"+url.PathEscape(name)+"/status", obj)
	if err != nil {
		return err
	}
	if st/100 != 2 {
		return fmt.Errorf("k8s: update trstctl TrustBundle %s status: %d: %s", name, st, string(body))
	}
	return nil
}

func trustBundleReadyCondition(targets trustBundleTargets) map[string]any {
	return map[string]any{
		"type":    "Ready",
		"status":  "True",
		"reason":  "Distributed",
		"message": targets.message(),
	}
}

func upsertTrustBundleReady(existing any, targets trustBundleTargets) []any {
	ready := trustBundleReadyCondition(targets)
	conds, _ := existing.([]any)
	for i, c := range conds {
		if m, ok := c.(map[string]any); ok && m["type"] == "Ready" {
			conds[i] = ready
			return conds
		}
	}
	return append(conds, ready)
}
