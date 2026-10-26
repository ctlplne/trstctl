// SPDX-License-Identifier: BUSL-1.1

package k8s

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"strings"

	"trstctl.com/trstctl/internal/crypto"
)

func configMapCollectionPath(namespace string) string {
	return fmt.Sprintf("/api/v1/namespaces/%s/configmaps", namespace)
}

func configMapItemPath(namespace, name string) string {
	return configMapCollectionPath(namespace) + "/" + name
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
	posture := make([]PostureResource, 0, len(list.Items))
	for _, bundle := range list.Items {
		n, current, err := c.syncTrustBundle(ctx, bundle)
		posture = append(posture, current)
		if err != nil {
			return writes, posture, err
		}
		writes += n
	}
	return writes, posture, nil
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
	var none trustBundleTargets
	name := objectName(obj)
	if name == "" {
		return 0, none, "", fmt.Errorf("k8s: trstctl TrustBundle missing metadata.name")
	}
	spec, _ := obj["spec"].(map[string]any)
	if spec == nil {
		return 0, none, "", permanent(fmt.Errorf("k8s: trstctl TrustBundle %s missing spec", name))
	}
	target, _ := spec["target"].(map[string]any)
	configMapName := nativeString(target, "configMapName")
	if configMapName == "" {
		configMapName = name
	}
	key := nativeString(target, "key")
	if key == "" {
		key = "ca-bundle.pem"
	}
	namespaces := nativeStringList(target["namespaces"])
	if len(namespaces) == 0 {
		return 0, none, "", permanent(fmt.Errorf("k8s: trstctl TrustBundle %s missing spec.target.namespaces", name))
	}
	bundlePEM, hash, err := trustBundlePEM(spec)
	if err != nil {
		return 0, none, "", permanent(fmt.Errorf("k8s: trstctl TrustBundle %s: %w", name, err))
	}
	secretTarget, err := parseTrustSecretTarget(target)
	if err != nil {
		return 0, none, "", permanent(fmt.Errorf("k8s: trstctl TrustBundle %s: %w", name, err))
	}
	clusterTrustBundle, err := parseClusterTrustBundleTarget(target)
	if err != nil {
		return 0, none, "", permanent(fmt.Errorf("k8s: trstctl TrustBundle %s: %w", name, err))
	}

	targets := trustBundleTargets{Namespaces: len(namespaces), ClusterTrustBundle: clusterTrustBundle}
	written := 0
	count := func(wrote bool) {
		if wrote {
			written++
		}
	}
	for _, namespace := range namespaces {
		dest := configMapDestination{client: c.client, namespace: namespace, name: configMapName, bundleName: name}
		wrote, err := dest.Install(ctx, key, bundlePEM, hash)
		if err != nil {
			return written, targets, "", err
		}
		count(wrote)
		if secretTarget != nil {
			wrote, err := c.installTrustSecret(ctx, namespace, name, *secretTarget, bundlePEM, hash)
			if err != nil {
				return written, targets, "", err
			}
			count(wrote)
			targets.Secrets++
		}
	}
	if clusterTrustBundle != "" {
		wrote, err := c.installClusterTrustBundle(ctx, clusterTrustBundle, name, bundlePEM, hash)
		if err != nil {
			return written, targets, "", err
		}
		count(wrote)
	}
	return written, targets, hash, nil
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
	bundle := nativeString(spec, "caBundlePEM")
	if bundle == "" {
		return "", "", fmt.Errorf("spec.caBundlePEM is required")
	}
	bundle = strings.TrimSpace(bundle) + "\n"
	if err := validateTrustBundlePEM(bundle); err != nil {
		return "", "", err
	}
	return bundle, crypto.SHA256Hex([]byte(bundle)), nil
}

func validateTrustBundlePEM(bundle string) error {
	rest := []byte(strings.TrimSpace(bundle))
	certs := 0
	for {
		rest = bytes.TrimSpace(rest)
		if len(rest) == 0 {
			break
		}
		block, next := pem.Decode(rest)
		if block == nil {
			return fmt.Errorf("spec.caBundlePEM must contain only PEM CERTIFICATE blocks")
		}
		if block.Type != "CERTIFICATE" {
			return fmt.Errorf("spec.caBundlePEM contains %s block; only CERTIFICATE blocks are allowed", block.Type)
		}
		certs++
		rest = next
	}
	if certs == 0 {
		return fmt.Errorf("spec.caBundlePEM must contain at least one CERTIFICATE block")
	}
	return nil
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
	status, body, err := d.client.request(ctx, http.MethodGet, configMapItemPath(d.namespace, d.name), nil)
	if err != nil {
		return false, err
	}
	if status == http.StatusOK {
		var live map[string]any
		if err := json.Unmarshal(body, &live); err != nil {
			return false, fmt.Errorf("k8s: decode configmap %s/%s: %w", d.namespace, d.name, err)
		}
		meta, _ := live["metadata"].(map[string]any)
		if meta == nil {
			meta = map[string]any{}
		}
		labels, _ := meta["labels"].(map[string]any)
		annotations, _ := meta["annotations"].(map[string]any)
		data, _ := live["data"].(map[string]any)
		if data[key] == bundlePEM && labels["app.kubernetes.io/managed-by"] == "trstctl-agent" &&
			labels["trstctl.com/trust-bundle"] == d.bundleName && annotations["trstctl.com/bundle-sha256"] == hash {
			return false, nil
		}
		if labels == nil {
			labels = map[string]any{}
		}
		if annotations == nil {
			annotations = map[string]any{}
		}
		if data == nil {
			data = map[string]any{}
		}
		labels["app.kubernetes.io/managed-by"] = "trstctl-agent"
		labels["trstctl.com/trust-bundle"] = d.bundleName
		annotations["trstctl.com/bundle-sha256"] = hash
		data[key] = bundlePEM
		meta["labels"], meta["annotations"] = labels, annotations
		live["metadata"], live["data"] = meta, data
		return true, d.put(ctx, live)
	}
	meta := map[string]any{
		"name":      d.name,
		"namespace": d.namespace,
		"labels": map[string]string{
			"app.kubernetes.io/managed-by": "trstctl-agent",
			"trstctl.com/trust-bundle":     d.bundleName,
		},
		"annotations": map[string]string{
			"trstctl.com/bundle-sha256": hash,
		},
	}
	st, rb, err := d.client.request(ctx, http.MethodPost, configMapCollectionPath(d.namespace), configMapObject(meta, map[string]string{key: bundlePEM}))
	if err != nil {
		return false, err
	}
	if st == http.StatusConflict {
		// Created meanwhile: converge against what is there now.
		return d.Install(ctx, key, bundlePEM, hash)
	}
	if st/100 != 2 {
		return false, fmt.Errorf("k8s: create configmap %s/%s: status %d: %s", d.namespace, d.name, st, string(rb))
	}
	return true, nil
}

func (d configMapDestination) put(ctx context.Context, obj map[string]any) error {
	st, rb, err := d.client.request(ctx, http.MethodPut, configMapItemPath(d.namespace, d.name), obj)
	if err != nil {
		return err
	}
	if st/100 != 2 {
		return fmt.Errorf("k8s: update configmap %s/%s: status %d: %s", d.namespace, d.name, st, string(rb))
	}
	return nil
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
	name := objectName(obj)
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

	st, body, err := c.client.request(ctx, http.MethodPut, trustBundleCollectionPath()+"/"+name+"/status", obj)
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
	name := objectName(obj)
	if name == "" {
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
	st, body, err := c.client.request(ctx, http.MethodPut, trustBundleCollectionPath()+"/"+name+"/status", obj)
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
