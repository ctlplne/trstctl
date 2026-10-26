// SPDX-License-Identifier: BUSL-1.1

package k8s

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"sync"

	"trstctl.com/trstctl/internal/crypto/secret"
)

// A139: besides the namespace ConfigMap, a TrustBundle can be distributed as a
// Secret in each target namespace (for consumers that read CA bundles from
// Secrets) and as a ClusterTrustBundle, which pods mount through a projected
// `clusterTrustBundle` volume source. Both hold public CA certificates only and
// are labeled as the agent's own; the agent never takes over an object of the
// same name that someone else created.

var (
	trustObjectNameRE = regexp.MustCompile(`^[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?$`)
	trustDataKeyRE    = regexp.MustCompile(`^[-._a-zA-Z0-9]{1,253}$`)
)

// trustBundleTargets is where one bundle is distributed.
type trustBundleTargets struct {
	Namespaces         int
	Secrets            int
	ClusterTrustBundle string
}

func (t trustBundleTargets) message() string {
	msg := fmt.Sprintf("trstctl TrustBundle distributed to %d namespace targets", t.Namespaces)
	if t.Secrets > 0 {
		msg += fmt.Sprintf(", as a Secret in %d", t.Secrets)
	}
	if t.ClusterTrustBundle != "" {
		msg += ", and as ClusterTrustBundle " + t.ClusterTrustBundle
	}
	return msg
}

// trustSecretTarget is spec.target.secret, or nil when the bundle names none.
type trustSecretTarget struct{ name, key string }

func parseTrustSecretTarget(target map[string]any) (*trustSecretTarget, error) {
	raw, ok := target["secret"].(map[string]any)
	if !ok || raw == nil {
		return nil, nil
	}
	out := &trustSecretTarget{name: nativeString(raw, "name"), key: nativeString(raw, "key")}
	if out.key == "" {
		out.key = "ca.crt"
	}
	if !trustObjectNameRE.MatchString(out.name) || !trustDataKeyRE.MatchString(out.key) {
		return nil, fmt.Errorf("spec.target.secret needs a Kubernetes object name and a data key")
	}
	return out, nil
}

func parseClusterTrustBundleTarget(target map[string]any) (string, error) {
	raw, ok := target["clusterTrustBundle"].(map[string]any)
	if !ok || raw == nil {
		return "", nil
	}
	name := nativeString(raw, "name")
	// A ClusterTrustBundle without a signer name may not contain ':'.
	if !trustObjectNameRE.MatchString(name) {
		return "", fmt.Errorf("spec.target.clusterTrustBundle.name must be a Kubernetes object name")
	}
	return name, nil
}

func trustObjectOwned(meta map[string]any, bundleName string) bool {
	labels, _ := meta["labels"].(map[string]any)
	return labels["app.kubernetes.io/managed-by"] == "trstctl-agent" && labels["trstctl.com/trust-bundle"] == bundleName
}

func trustObjectLabels(bundleName string) map[string]any {
	return map[string]any{"app.kubernetes.io/managed-by": "trstctl-agent", "trstctl.com/trust-bundle": bundleName}
}

// installTrustSecret makes an Opaque Secret in namespace hold the bundle under
// key, reporting whether it wrote. A Secret the agent did not create is never
// changed. Writing Secrets outside the agent's namespace needs the opt-in grant
// in deploy/kubernetes/rbac-trust-secrets.yaml.
func (c *IssuerController) installTrustSecret(ctx context.Context, namespace, bundleName string, target trustSecretTarget, bundlePEM, hash string) (bool, error) {
	path := fmt.Sprintf("/api/v1/namespaces/%s/secrets/%s", namespace, target.name)
	st, body, err := c.client.request(ctx, http.MethodGet, path, nil)
	defer secret.Wipe(body)
	if err != nil {
		return false, err
	}
	switch {
	case st == http.StatusForbidden:
		return false, fmt.Errorf("k8s: the agent may not read Secret %s/%s; apply deploy/kubernetes/rbac-trust-secrets.yaml to allow TrustBundle Secret targets", namespace, target.name)
	case st == http.StatusNotFound:
		obj := map[string]any{
			"apiVersion": "v1", "kind": "Secret", "type": "Opaque",
			"metadata": map[string]any{
				"name": target.name, "namespace": namespace, "labels": trustObjectLabels(bundleName),
				"annotations": map[string]any{"trstctl.com/bundle-sha256": hash},
			},
			"data": map[string]any{target.key: base64.StdEncoding.EncodeToString([]byte(bundlePEM))},
		}
		st, created, err := c.client.request(ctx, http.MethodPost, fmt.Sprintf("/api/v1/namespaces/%s/secrets", namespace), obj)
		secret.Wipe(created)
		if err != nil {
			return false, err
		}
		if st == http.StatusForbidden {
			return false, fmt.Errorf("k8s: the agent may not create Secret %s/%s; apply deploy/kubernetes/rbac-trust-secrets.yaml to allow TrustBundle Secret targets", namespace, target.name)
		}
		if st/100 != 2 {
			return false, fmt.Errorf("k8s: create Secret %s/%s: status %d", namespace, target.name, st)
		}
		return true, nil
	case st/100 != 2:
		return false, fmt.Errorf("k8s: read Secret %s/%s: status %d", namespace, target.name, st)
	}
	var live map[string]any
	if err := json.Unmarshal(body, &live); err != nil {
		return false, fmt.Errorf("k8s: decode Secret %s/%s: %w", namespace, target.name, err)
	}
	meta, _ := live["metadata"].(map[string]any)
	if !trustObjectOwned(meta, bundleName) {
		return false, fmt.Errorf("k8s: Secret %s/%s exists and was not created for TrustBundle %s; rename the target or remove it", namespace, target.name, bundleName)
	}
	data, _ := live["data"].(map[string]any)
	if data == nil {
		data = map[string]any{}
	}
	encoded := base64.StdEncoding.EncodeToString([]byte(bundlePEM))
	annotations, _ := meta["annotations"].(map[string]any)
	if data[target.key] == encoded && annotations["trstctl.com/bundle-sha256"] == hash {
		return false, nil
	}
	if annotations == nil {
		annotations = map[string]any{}
	}
	annotations["trstctl.com/bundle-sha256"] = hash
	meta["annotations"] = annotations
	data[target.key] = encoded
	live["data"] = data
	st, updated, err := c.client.request(ctx, http.MethodPut, path, live)
	secret.Wipe(updated)
	if err != nil {
		return false, err
	}
	if st/100 != 2 {
		return false, fmt.Errorf("k8s: update Secret %s/%s: status %d", namespace, target.name, st)
	}
	return true, nil
}

type discoveryResource struct {
	Name string `json:"name"`
}

// clusterTrustBundleAPI finds the certificates.k8s.io version that serves
// ClusterTrustBundle (beta, then alpha), once per controller.
type clusterTrustBundleAPI struct {
	mu      sync.Mutex
	version string
}

func (a *clusterTrustBundleAPI) resolve(ctx context.Context, client *Client) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.version != "" {
		return a.version, nil
	}
	for _, version := range []string{"v1beta1", "v1alpha1"} {
		st, body, err := client.request(ctx, http.MethodGet, "/apis/certificates.k8s.io/"+version, nil)
		if err != nil {
			return "", err
		}
		if st != http.StatusOK {
			continue
		}
		var discovery struct {
			Resources []discoveryResource `json:"resources"`
		}
		if json.Unmarshal(body, &discovery) == nil && slices.ContainsFunc(discovery.Resources, func(r discoveryResource) bool {
			return r.Name == "clustertrustbundles"
		}) {
			a.version = version
			return version, nil
		}
	}
	return "", fmt.Errorf("k8s: this cluster does not serve the ClusterTrustBundle API; enable certificates.k8s.io/v1beta1 clustertrustbundles (and the ClusterTrustBundle and ClusterTrustBundleProjection feature gates) to use spec.target.clusterTrustBundle")
}

// installClusterTrustBundle makes the named ClusterTrustBundle hold the
// bundle, reporting whether it wrote.
func (c *IssuerController) installClusterTrustBundle(ctx context.Context, name, bundleName, bundlePEM, hash string) (bool, error) {
	version, err := c.clusterTrustBundles.resolve(ctx, c.client)
	if err != nil {
		return false, err
	}
	collection := "/apis/certificates.k8s.io/" + version + "/clustertrustbundles"
	st, body, err := c.client.request(ctx, http.MethodGet, collection+"/"+name, nil)
	if err != nil {
		return false, err
	}
	if st == http.StatusNotFound {
		obj := map[string]any{
			"apiVersion": "certificates.k8s.io/" + version, "kind": "ClusterTrustBundle",
			"metadata": map[string]any{
				"name": name, "labels": trustObjectLabels(bundleName),
				"annotations": map[string]any{"trstctl.com/bundle-sha256": hash},
			},
			"spec": map[string]any{"trustBundle": bundlePEM},
		}
		st, created, err := c.client.request(ctx, http.MethodPost, collection, obj)
		if err != nil {
			return false, err
		}
		if st/100 != 2 {
			return false, fmt.Errorf("k8s: create ClusterTrustBundle %s: status %d: %s", name, st, string(created))
		}
		return true, nil
	}
	if st/100 != 2 {
		return false, fmt.Errorf("k8s: read ClusterTrustBundle %s: status %d: %s", name, st, string(body))
	}
	var live map[string]any
	if err := json.Unmarshal(body, &live); err != nil {
		return false, fmt.Errorf("k8s: decode ClusterTrustBundle %s: %w", name, err)
	}
	meta, _ := live["metadata"].(map[string]any)
	if !trustObjectOwned(meta, bundleName) {
		return false, fmt.Errorf("k8s: ClusterTrustBundle %s exists and was not created for TrustBundle %s; rename the target or remove it", name, bundleName)
	}
	spec, _ := live["spec"].(map[string]any)
	if current, _ := spec["trustBundle"].(string); bytes.Equal([]byte(current), []byte(bundlePEM)) {
		return false, nil
	}
	if spec == nil {
		spec = map[string]any{}
	}
	spec["trustBundle"] = bundlePEM
	live["spec"] = spec
	annotations, _ := meta["annotations"].(map[string]any)
	if annotations == nil {
		annotations = map[string]any{}
	}
	annotations["trstctl.com/bundle-sha256"] = hash
	meta["annotations"] = annotations
	st, updated, err := c.client.request(ctx, http.MethodPut, collection+"/"+name, live)
	if err != nil {
		return false, err
	}
	if st/100 != 2 {
		return false, fmt.Errorf("k8s: update ClusterTrustBundle %s: status %d: %s", name, st, string(updated))
	}
	return true, nil
}
