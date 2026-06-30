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

func (c *IssuerController) reconcileTrustBundles(ctx context.Context) (int, error) {
	st, body, err := c.client.request(ctx, http.MethodGet, trustBundleCollectionPath(), nil)
	if err != nil {
		return 0, err
	}
	if st == http.StatusNotFound {
		return 0, nil
	}
	if st/100 != 2 {
		return 0, fmt.Errorf("k8s: list trstctl TrustBundle resources: status %d: %s", st, string(body))
	}
	var list struct {
		Items []map[string]any `json:"items"`
	}
	if err := json.Unmarshal(body, &list); err != nil {
		return 0, fmt.Errorf("k8s: decode trstctl TrustBundle list: %w", err)
	}

	writes := 0
	for _, bundle := range list.Items {
		n, hash, err := c.distributeTrustBundle(ctx, bundle)
		if err != nil {
			return writes, err
		}
		if n == 0 {
			continue
		}
		writes += n
		if err := c.markTrustBundleReady(ctx, bundle, n, hash); err != nil {
			return writes, err
		}
	}
	return writes, nil
}

func (c *IssuerController) distributeTrustBundle(ctx context.Context, obj map[string]any) (int, string, error) {
	name := objectName(obj)
	if name == "" {
		return 0, "", fmt.Errorf("k8s: trstctl TrustBundle missing metadata.name")
	}
	spec, _ := obj["spec"].(map[string]any)
	if spec == nil {
		return 0, "", fmt.Errorf("k8s: trstctl TrustBundle %s missing spec", name)
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
		return 0, "", fmt.Errorf("k8s: trstctl TrustBundle %s missing spec.target.namespaces", name)
	}
	bundlePEM, hash, err := trustBundlePEM(spec)
	if err != nil {
		return 0, "", fmt.Errorf("k8s: trstctl TrustBundle %s: %w", name, err)
	}

	for _, namespace := range namespaces {
		dest := configMapDestination{client: c.client, namespace: namespace, name: configMapName, bundleName: name}
		if err := dest.Install(ctx, key, bundlePEM, hash); err != nil {
			return 0, "", err
		}
	}
	return len(namespaces), hash, nil
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

func (d configMapDestination) Install(ctx context.Context, key, bundlePEM, hash string) error {
	data := map[string]string{key: bundlePEM}
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

	status, body, err := d.client.request(ctx, http.MethodGet, configMapItemPath(d.namespace, d.name), nil)
	if err != nil {
		return err
	}
	if status == http.StatusOK {
		if rv := resourceVersion(body); rv != "" {
			meta["resourceVersion"] = rv
		}
		return d.put(ctx, configMapObject(meta, data))
	}
	st, rb, err := d.client.request(ctx, http.MethodPost, configMapCollectionPath(d.namespace), configMapObject(meta, data))
	if err != nil {
		return err
	}
	if st == http.StatusConflict {
		return d.put(ctx, configMapObject(meta, data))
	}
	if st/100 != 2 {
		return fmt.Errorf("k8s: create configmap %s/%s: status %d: %s", d.namespace, d.name, st, string(rb))
	}
	return nil
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

func (c *IssuerController) markTrustBundleReady(ctx context.Context, obj map[string]any, targets int, hash string) error {
	name := objectName(obj)
	status, _ := obj["status"].(map[string]any)
	if status == nil {
		status = map[string]any{}
	}
	status["targets"] = targets
	status["bundleSHA256"] = hash
	status["conditions"] = upsertTrustBundleReady(status["conditions"], targets)
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

func upsertTrustBundleReady(existing any, targets int) []any {
	ready := map[string]any{
		"type":    "Ready",
		"status":  "True",
		"reason":  "Distributed",
		"message": fmt.Sprintf("trstctl TrustBundle distributed to %d namespace targets", targets),
	}
	conds, _ := existing.([]any)
	for i, c := range conds {
		if m, ok := c.(map[string]any); ok && m["type"] == "Ready" {
			conds[i] = ready
			return conds
		}
	}
	return append(conds, ready)
}
